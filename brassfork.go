package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"flag"
	"fmt"
	"net"
	"os"
)

type Object struct {
	SourceIP   string
	SourceName string
	TargetIP   string
	TargetName string
	Service    string
	Packages   int
	Bytes      int
	Syns       int
}

type Node struct {
	ID    string
	Label string
}

func lookup_addr(addr string) string {
	result := ""
	addrs, _ := net.LookupAddr(addr)
	if addrs != nil && len(addrs) > 0 {
		result = addrs[0]
	}
	return result
}

func read_packets(messages chan int, cs chan Object, in_filename string) {
	if handle, err := pcap.OpenOffline(in_filename); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			result := Object{Packages: 1}

			// IPv4 LayerTypeIPv4
			if ipv4_layer := packet.Layer(layers.LayerTypeIPv4); ipv4_layer != nil {
				ipv4, _ := ipv4_layer.(*layers.IPv4)
				result.Bytes = int(ipv4.Length)
				result.SourceIP = ipv4.SrcIP.String()
				result.TargetIP = ipv4.DstIP.String()
			}

			// IPv6 LayerTypeIPv6
			if ipv6_layer := packet.Layer(layers.LayerTypeIPv6); ipv6_layer != nil {
				ipv6, _ := ipv6_layer.(*layers.IPv6)
				result.Bytes = int(ipv6.Length)
				result.SourceIP = ipv6.SrcIP.String()
				result.TargetIP = ipv6.DstIP.String()
			}

			// TCP
			if tcp_layer := packet.Layer(layers.LayerTypeTCP); tcp_layer != nil {
				tcp, _ := tcp_layer.(*layers.TCP)
				result.Service = fmt.Sprintf("%v/TCP", tcp.DstPort)
				if tcp.SYN {
					result.Syns = 1
				}
			}

			// UDP
			if udp_layer := packet.Layer(layers.LayerTypeUDP); udp_layer != nil {
				udp, _ := udp_layer.(*layers.UDP)
				result.Service = fmt.Sprintf("%v/UDP", udp.DstPort)
			}

			// SCTP
			if sctp_layer := packet.Layer(layers.LayerTypeSCTP); sctp_layer != nil {
				sctp, _ := sctp_layer.(*layers.SCTP)
				result.Service = fmt.Sprintf("%v/SCTP", sctp.DstPort)
			}

			cs <- result

		}
	}
	messages <- 1
	close(cs)
}

func count_packets(messages chan int, cs chan Object, packets map[string]Object) {
	for packet := range cs {
		key := packet.SourceIP + "," + packet.TargetIP + "," + packet.Service

		// Exists already?
		if p, ok := packets[key]; ok {
			// Existed, add just Packages + Bytes + Syns
			p.Bytes = p.Bytes + packet.Bytes
			p.Packages = p.Packages + 1
			p.Syns = p.Syns + packet.Syns
			packets[key] = p
		} else {
			// Did not exist, add
			packets[key] = packet
		}
	}
	messages <- 2

}

func write_nodes_to_file(out_filename string, packets map[string]Object) {
	f, err := os.Create(out_filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Headers
	f.WriteString("Id,Label\n")

	// Get all mentioned nodes, remove duplicates..
	nodes := make(map[string]Node)

	for _, packet := range packets {
		nodes[packet.SourceIP] = Node{ID: packet.SourceIP, Label: lookup_addr(packet.SourceIP)}
		nodes[packet.TargetIP] = Node{ID: packet.TargetIP, Label: lookup_addr(packet.TargetIP)}
	}

	for _, v := range nodes {
		if v.ID != "" && v.Label != "" {
			f.WriteString(fmt.Sprintf("%v,%v\n", v.ID, v.Label))
		}
	}
}

func write_edges_to_file(out_filename string, packets map[string]Object) {
	f, err := os.Create(out_filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Headers
	f.WriteString("Source,Target,Type,Label,Weight,Bytes,Packages,SYNs\n")

	for _, packet := range packets {
		f.WriteString(fmt.Sprintf("%v,%v,Directed,%v,%v,%v,%v,%v\n",
			packet.SourceIP, packet.TargetIP, packet.Service, packet.Bytes, packet.Bytes, packet.Packages, packet.Syns))
	}

}

func main() {
	var pcap_file = flag.String("in", "", "pcap file")
	var nodes_file = flag.String("nodes", "", "node file")
	var edges_file = flag.String("edges", "", "edge file")
	flag.Parse()

	if *pcap_file == "" || *nodes_file == "" || *edges_file == "" {
		flag.PrintDefaults()
		return
	}

	objs := make(map[string]Object, 1000)

	cs := make(chan Object)
	messages := make(chan int)

	go read_packets(messages, cs, *pcap_file)
	go count_packets(messages, cs, objs)

	for i := 0; i < 2; i++ {
		// Wait for every goroutine to signal something
		<-messages
	}

	// Instead of using goroutines, this is easier for gathering the aggregates...
	write_nodes_to_file(*nodes_file, objs)
	write_edges_to_file(*edges_file, objs)
}
