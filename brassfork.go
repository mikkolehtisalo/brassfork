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
	"runtime/pprof"
	"sync"
	"time"
)

var (
	dcache dns_cache
)

type dns_cache struct {
	mu             sync.Mutex
	resolved_names map[string]string
}

func (d *dns_cache) Put(key string, value string) {
	d.mu.Lock()
	d.resolved_names[key] = value
	d.mu.Unlock()
}

func (d *dns_cache) Get(key string) string {
	result := ""
	d.mu.Lock()
	if r, ok := d.resolved_names[key]; ok {
		result = r
	}
	d.mu.Unlock()
	return result
}

// Used for generating network names for Nodes
type Network struct {
	CIDR  string
	Name  string
	ipnet *net.IPNet
}

// Used for gathering most of the data
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

// Tries to reverse resolve ip address. Returns addr if unsuccessful.
func lookup_addr(addr string) string {
	result := dcache.Get(addr)
	if result == "" {
		addrs, _ := net.LookupAddr(addr)
		if addrs != nil && len(addrs) > 0 {
			result = addrs[0]
			dcache.Put(addr, addrs[0])
		}
	}
	if result == "" {
		result = addr
	}
	return result
}

// Gets source and target IPs from packet, if it is either IPv4 or IPv6
func get_ips(packet *gopacket.Packet) (string, string) {
	src := ""
	tgt := ""

	// IPv4
	if ipv4_layer := (*packet).Layer(layers.LayerTypeIPv4); ipv4_layer != nil {
		ipv4, _ := ipv4_layer.(*layers.IPv4)
		src = ipv4.SrcIP.String()
		tgt = ipv4.DstIP.String()
	} else // Can't be both v4 and v6!

	// IPv6
	if ipv6_layer := (*packet).Layer(layers.LayerTypeIPv6); ipv6_layer != nil {
		ipv6, _ := ipv6_layer.(*layers.IPv6)
		src = ipv6.SrcIP.String()
		tgt = ipv6.DstIP.String()
	}

	return src, tgt
}

// Read the packets from file, gather some very basic information, and forward the information to other goroutines.
// Does not check for pcap parsing errors, but those should be rare for the most common layer types...
func read_packets(messages chan int, cs chan Object, cs2 chan gopacket.Packet, in_filename string) {
	if handle, err := pcap.OpenOffline(in_filename); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.Lazy = true
		packetSource.NoCopy = true
		for packet := range packetSource.Packets() {
			result := Object{
				Packages: 1,
				Bytes:    packet.Metadata().Length}

			result.SourceIP, result.TargetIP = get_ips(&packet)

			// TCP
			if tcp_layer := packet.Layer(layers.LayerTypeTCP); tcp_layer != nil {
				tcp, _ := tcp_layer.(*layers.TCP)
				// Calls String(), which may return "number(name)" or "number"
				result.Service = tcp.DstPort.String()
				result.Protocol = "TCP"
				if tcp.SYN {
					result.Syns = 1
				}
				if tcp.FIN {
					result.Fins = 1
				}
			} else // Try UDP next

			// UDP
			if udp_layer := packet.Layer(layers.LayerTypeUDP); udp_layer != nil {
				udp, _ := udp_layer.(*layers.UDP)
				// Calls String(), which may return "number(name)" or "number"
				result.Service = udp.DstPort.String()
				result.Protocol = "UDP"
			} else // Try SCTP next

			// SCTP
			if sctp_layer := packet.Layer(layers.LayerTypeSCTP); sctp_layer != nil {
				sctp, _ := sctp_layer.(*layers.SCTP)
				// Calls String(), which may return "number(name)" or "number"
				result.Service = sctp.DstPort.String()
				result.Protocol = "SCTP"
			}

			// Only forward this packet, if we got the basic information about the packet
			// This rules out packages such as dhcp
			if result.SourceIP != "" && result.TargetIP != "" && result.Protocol != "" {
				cs <- result
				cs2 <- packet
			}

		}
	}

	fmt.Printf("Read all packets\n")
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
	fmt.Printf("Counted basic statistics\n")
	messages <- 2
}

// Tracks TCP connection statuses
func track_tcp_connections(messages chan int, cs chan gopacket.Packet, conns *[]Connection) {
	for packet := range cs {

		src, tgt := get_ips(&packet)
		svc := ""
		ts := packet.Metadata().Timestamp
		seq := uint32(0)
		syn := false
		fin := false

		// Gather info from TCP layer
		if tcp_layer := packet.Layer(layers.LayerTypeTCP); tcp_layer != nil {
			tcp, _ := tcp_layer.(*layers.TCP)
			// Calls String(), which may return "number(name)" or "number"
			svc = tcp.DstPort.String()
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
				// (there should be a matching FIN anyways, discarding only the second one doesn't usually change the end result)
				for i := 0; i < len(*conns); i++ {
					if (*conns)[i].SourceIP == src && (*conns)[i].TargetIP == tgt && (*conns)[i].Service == svc && (*conns)[i].Sequence+1 == seq {
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

	fmt.Printf("Tracking TCP status ready\n")
	messages <- 3
}

// Calculate average time (TCP, limited by generated input data) connections on edge have taken
// Process only connections that have both start and end timestamps
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
		result = int(sum / int64(len(matching)))
	}

	return result
}

// Writes node information to file, in format Gephi knows how to import
func write_nodes_to_file(out_filename string, packets map[string]Object, networks []Network) {
	f, err := os.Create(out_filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Headers
	f.WriteString("Id,Label,Network\n")

	// Get all mentioned nodes, remove duplicates..
	nodes := make(map[string]*Node)
	for _, packet := range packets {
		nodes[packet.SourceIP] = &(Node{ID: packet.SourceIP})
		nodes[packet.TargetIP] = &(Node{ID: packet.TargetIP})
	}

	// Parallel lookups
	var wg sync.WaitGroup
	for x, _ := range nodes {
		wg.Add(1)
		go func(n *Node, networks []Network) {
			// Decrement counter
			defer wg.Done()
			// Lookup
			n.Label = lookup_addr(n.ID)
			n.Network = get_network(networks, n.ID)
		}(nodes[x], networks)
	}
	// Wait for all lookups to complete
	wg.Wait()

	// Print the nodes
	for x, _ := range nodes {
		if nodes[x].ID != "" {
			f.WriteString(fmt.Sprintf("%v,%v,%v\n", nodes[x].ID, nodes[x].Label, nodes[x].Network))
		}
	}
}

// Writes edge information to file, in format Gephi knows how to import
func write_edges_to_file(out_filename string, packets map[string]Object, conns []Connection) {
	f, err := os.Create(out_filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Headers
	f.WriteString("Source,Target,Type,Label,Protocol,Weight,Bytes,Packages,SYNs,FINs,Unfinished,Avg\n")

	for _, packet := range packets {
		unf := 0
		avg := 0
		if packet.Protocol == "TCP" {
			unf = packet.Syns - packet.Fins
			// It's possible we missed some in the capture itself...
			// There's no point reporting negative number
			if unf < 0 {
				unf = 0
			}
			// Average time TCP connections took on this edge
			avg = get_avg_tcp(conns, packet)
		}
		f.WriteString(fmt.Sprintf("%v,%v,Directed,%v,%v,%v,%v,%v,%v,%v,%v,%v\n",
			packet.SourceIP, packet.TargetIP, packet.Service, packet.Protocol,
			packet.Bytes, packet.Bytes, packet.Packages, packet.Syns, packet.Fins, unf, avg))
	}

}

// Names the network the IP belongs to, if the name is known
func get_network(networks []Network, ip_str string) string {
	result := ""

	if ip := net.ParseIP(ip_str); ip != nil {
		for x := 0; x < len(networks); x++ {
			if networks[x].ipnet.Contains(ip) {
				result = networks[x].Name
			}
		}
	}

	return result
}

// Reads networks information in JSON format for naming networks of Nodes
func read_networks(networks_filename string) []Network {
	networks := []Network{}

	// Reading the string versions
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

	// Generating IPNets
	// Alternatively could have implemented custom JSON unmarshaler
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
	var cpu_profile = flag.String("cpuprofile", "", "cpu profile to file")

	flag.Parse()

	if *pcap_file == "" || *nodes_file == "" || *edges_file == "" {
		flag.PrintDefaults()
		return
	}

	if *cpu_profile != "" {
		// Enable profiling
		f, err := os.Create(*cpu_profile)
		if err != nil {
			panic(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	dcache.resolved_names = make(map[string]string)
	/*
	   var (
	   	dcache dns_cache
	   )

	   type dns_cache struct {
	   	mu             sync.Mutex
	   	resolved_names map[string]string
	   }

	*/
	nets := read_networks(*networks_file)

	conns := []Connection{}

	objs := make(map[string]Object)
	cs := make(chan Object, 1000000)
	cs2 := make(chan gopacket.Packet, 1000000)
	messages := make(chan int)

	// Read packets and their basic information
	go read_packets(messages, cs, cs2, *pcap_file)
	// Aggregate basic statistics
	go count_packets(messages, cs, objs)
	// Track the TCP connection durations
	go track_tcp_connections(messages, cs2, &conns)

	for i := 0; i < 3; i++ {
		// Wait for every goroutine to signal something
		<-messages
	}

	// Easier approach than attempting to do this with channels
	write_nodes_to_file(*nodes_file, objs, nets)
	fmt.Printf("Writing nodes finished\n")
	write_edges_to_file(*edges_file, objs, conns)
	fmt.Printf("Writing edges finished\n")
}
