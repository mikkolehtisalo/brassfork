package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"
)

type Network struct {
	CIDR  string
	Name  string
	ipnet *net.IPNet
}

type Object struct {
	SourceIP   string
	SourceName string
	TargetIP   string
	TargetName string
	Service    string
	Protocol   string
	Packages   int
	Bytes      int
	Syns       int
	Fins       int
}

// Helper struct for write_nodes_to_file
type Node struct {
	ID      string
	Label   string
	Network string
}

// Used in tracking the duration of connections
type Connection struct {
	SourceIP string
	TargetIP string
	Service  string
	Sequence uint32
	SynTime  time.Time
	FinTime  time.Time
}

// Tries to reverse resolve ip address
func lookup_addr(addr string) string {
	result := ""
	addrs, _ := net.LookupAddr(addr)
	if addrs != nil && len(addrs) > 0 {
		result = addrs[0]
	}
	return result
}

func get_ips(packet gopacket.Packet) (string, string) {
	src := ""
	tgt := ""

	// IPv4 LayerTypeIPv4
	if ipv4_layer := packet.Layer(layers.LayerTypeIPv4); ipv4_layer != nil {
		ipv4, _ := ipv4_layer.(*layers.IPv4)
		src = ipv4.SrcIP.String()
		tgt = ipv4.DstIP.String()
	}

	// IPv6 LayerTypeIPv6
	if ipv6_layer := packet.Layer(layers.LayerTypeIPv6); ipv6_layer != nil {
		ipv6, _ := ipv6_layer.(*layers.IPv6)
		src = ipv6.SrcIP.String()
		tgt = ipv6.DstIP.String()
	}

	return src, tgt
}

func read_packets(messages chan int, cs chan Object, cs2 chan gopacket.Packet, in_filename string) {
	if handle, err := pcap.OpenOffline(in_filename); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			result := Object{
				Packages: 1,
				Bytes:    len(packet.Data())}

			result.SourceIP, result.TargetIP = get_ips(packet)

			// TCP
			if tcp_layer := packet.Layer(layers.LayerTypeTCP); tcp_layer != nil {
				tcp, _ := tcp_layer.(*layers.TCP)
				result.Service = fmt.Sprintf("%v", tcp.DstPort)
				result.Protocol = "TCP"
				if tcp.SYN {
					result.Syns = 1
				}
				if tcp.FIN {
					result.Fins = 1
				}
			}

			// UDP
			if udp_layer := packet.Layer(layers.LayerTypeUDP); udp_layer != nil {
				udp, _ := udp_layer.(*layers.UDP)
				result.Service = fmt.Sprintf("%v", udp.DstPort)
				result.Protocol = "UDP"
			}

			// SCTP
			if sctp_layer := packet.Layer(layers.LayerTypeSCTP); sctp_layer != nil {
				sctp, _ := sctp_layer.(*layers.SCTP)
				result.Service = fmt.Sprintf("%v", sctp.DstPort)
				result.Protocol = "SCTP"
			}

			cs <- result
			cs2 <- packet

		}
	}
	messages <- 1
	close(cs)
	close(cs2)
}

// Aggregate statistics for edges
func count_packets(messages chan int, cs chan Object, packets map[string]Object) {
	for packet := range cs {
		key := packet.SourceIP + "," + packet.TargetIP + "," + packet.Service + "," + packet.Protocol

		// Exists already?
		if p, ok := packets[key]; ok {
			// Existed, add just Packages + Bytes + Syns + Fins
			p.Bytes = p.Bytes + packet.Bytes
			p.Packages = p.Packages + 1
			p.Syns = p.Syns + packet.Syns
			p.Fins = p.Fins + packet.Fins
			packets[key] = p
		} else {
			// Did not exist, add
			packets[key] = packet
		}
	}
	messages <- 2
}

// Tracks TCP connection statuses
func track_tcp_connections(messages chan int, cs chan gopacket.Packet, conns *[]Connection) {
	//conns := []Connection{}

	for packet := range cs {

		src, tgt := get_ips(packet)
		svc := ""
		ts := packet.Metadata().Timestamp
		seq := uint32(0)
		syn := false
		fin := false

		// Gather info from TCP layer
		if tcp_layer := packet.Layer(layers.LayerTypeTCP); tcp_layer != nil {
			tcp, _ := tcp_layer.(*layers.TCP)
			svc = fmt.Sprintf("%v", tcp.DstPort)
			seq = tcp.Seq
			if tcp.SYN {
				syn = true

			}
			if tcp.FIN {
				fin = true
			}

			// Handle package information
			if syn {
				// New, so make a new connection
				conn := Connection{
					SynTime:  ts,
					SourceIP: src,
					TargetIP: tgt,
					Service:  svc,
					Sequence: seq}
				// Add to connections
				*conns = append(*conns, conn)
			} else {
				// Try to find matching package
				// .. This takes account only packages to one direction, but that should be okayish
				for i, x := range *conns {
					if x.SourceIP == src && x.TargetIP == tgt && x.Service == svc && x.Sequence+1 == seq {
						// Update sequence, and if fin the timestamp for that
						(*conns)[i].Sequence = seq
						if fin {
							(*conns)[i].FinTime = ts
						}
					}
				}
			}

		}
	}

	messages <- 3
}

func get_avg_tcp(conns []Connection, packet Object) int {
	result := 0

	matching := []Connection{}
	// First let's get all matching connections
	for _, x := range conns {
		if packet.SourceIP == x.SourceIP && packet.TargetIP == x.TargetIP && !x.SynTime.IsZero() && !x.FinTime.IsZero() {
			matching = append(matching, x)
		}
	}

	// If we found any, calculate avg
	if len(matching) > 0 {
		sum := int64(0)
		for _, k := range matching {
			diff := k.FinTime.Sub(k.SynTime)
			diffms := diff.Nanoseconds() / 1000000
			sum = sum + diffms
		}
		avg := int(sum / int64(len(matching)))
		result = avg
	}

	return result
}

func write_nodes_to_file(out_filename string, packets map[string]Object, networks []Network) {
	f, err := os.Create(out_filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Headers
	f.WriteString("Id,Label,Network\n")

	// Get all mentioned nodes, remove duplicates..
	nodes := make(map[string]Node)

	for _, packet := range packets {
		nodes[packet.SourceIP] = Node{ID: packet.SourceIP, Label: lookup_addr(packet.SourceIP), Network: get_network(networks, packet.SourceIP)}
		nodes[packet.TargetIP] = Node{ID: packet.TargetIP, Label: lookup_addr(packet.TargetIP), Network: get_network(networks, packet.TargetIP)}
	}

	for _, v := range nodes {
		if v.ID != "" && v.Label != "" {
			f.WriteString(fmt.Sprintf("%v,%v,%v\n", v.ID, v.Label, v.Network))
		}
	}
}

func write_edges_to_file(out_filename string, packets map[string]Object, conns []Connection) {
	f, err := os.Create(out_filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Headers
	f.WriteString("Source,Target,Type,Label,Protocol,Weight,Bytes,Packages,SYNs,FINs,Unfinished,Avg\n")

	for _, packet := range packets {
		if packet.SourceIP != "" && packet.TargetIP != "" {
			unf := 0
			avg := 0
			if packet.Protocol == "TCP" {
				unf = packet.Syns - packet.Fins
				// It's possible we missed some in the capture itself...
				// There's no point reporting negative number
				if unf < 0 {
					unf = 0
				}
				// conns
				avg = get_avg_tcp(conns, packet)
			}
			f.WriteString(fmt.Sprintf("%v,%v,Directed,%v,%v,%v,%v,%v,%v,%v,%v,%v\n",
				packet.SourceIP, packet.TargetIP, packet.Service, packet.Protocol,
				packet.Bytes, packet.Bytes, packet.Packages, packet.Syns, packet.Fins, unf, avg))
		}
	}

}

// Names the network the IP belongs to, if the name is known
func get_network(networks []Network, ip_str string) string {
	result := ""

	if ip := net.ParseIP(ip_str); ip != nil {
		for _, net := range networks {
			if net.ipnet.Contains(ip) {
				result = net.Name
			}
		}
	}

	return result
}

func read_networks(networks_filename string) []Network {
	networks := []Network{}

	// String representations...
	if networks_filename != "" {
		net_file, err := ioutil.ReadFile(networks_filename)
		if err != nil {
			panic(err)
		}

		err = json.Unmarshal(net_file, &networks)
		if err != nil {
			panic(err)
		}
	}

	// IPNets
	// Alternatively could have implemented custom unmarshaler
	for x, _ := range networks {
		_, net, err := net.ParseCIDR(networks[x].CIDR)
		if err != nil {
			panic(err)
		}

		networks[x].ipnet = net
	}

	return networks
}

func main() {
	var pcap_file = flag.String("in", "", "pcap file")
	var nodes_file = flag.String("nodes", "", "node file")
	var edges_file = flag.String("edges", "", "edge file")
	var networks_file = flag.String("networks", "", "networks file")

	flag.Parse()

	if *pcap_file == "" || *nodes_file == "" || *edges_file == "" {
		flag.PrintDefaults()
		return
	}

	nets := read_networks(*networks_file)

	conns := []Connection{}

	objs := make(map[string]Object, 1000)
	cs := make(chan Object)
	cs2 := make(chan gopacket.Packet)
	messages := make(chan int)

	go read_packets(messages, cs, cs2, *pcap_file)
	go count_packets(messages, cs, objs)
	go track_tcp_connections(messages, cs2, &conns)

	for i := 0; i < 3; i++ {
		// Wait for every goroutine to signal something
		<-messages
	}

	// Instead of using goroutines & channels, this is easier for calculating the aggregates...
	write_nodes_to_file(*nodes_file, objs, nets)
	write_edges_to_file(*edges_file, objs, conns)
}
