package captureArp

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device string = "enp4s0"
	snapShotLen int32 = 1024
	promiscuous bool = false
	timeout time.Duration = 30 * time.Second
	handle *pcap.Handle
)
func print_packet (packet gopacket.Packet){

	fmt.Printf("Packet Capture" );

	// decoding Ethernet layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet);
	if ethLayer != nil {
		fmt.Printf("Ethernet Header\n");
		if ethHeaders , ok := ethLayer.(*layers.Ethernet); ok {
			fmt.Printf("\tSrc MAC : %s\n", ethHeaders.SrcMAC.String());
			fmt.Printf("\tDest MAC : %s\n", ethHeaders.SrcMAC.String());
			fmt.Printf("\tEthere Type : %s\n", ethHeaders.EthernetType.String());
		} else {

			fmt.Printf("MalForm Ethernet header\n");
		}
	}else {

		fmt.Printf("MalForm Ethernet header\n");
	}

	// decoding Network Layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4);
	if ipLayer != nil {

		fmt.Printf("Ip Header\n" );
		if ipHeaders, ok := ipLayer.(*layers.IPv4); ok {
			fmt.Printf("\tSrc IP : %s\n", ipHeaders.SrcIP.String());
			fmt.Printf("\tDest IP : %s\n", ipHeaders.DstIP.String());
			fmt.Printf("IP Protocol : %s\n", ipHeaders.Protocol.String());
			fmt.Printf("\tIP Flags: %s\n", ipHeaders.Flags);
		}else {
			fmt.Printf("MalForm IP header\n");
		};
	}else {
		fmt.Printf("MalForm IP header\n");
	}

	println("------------------------------------");
}

func arp_operation(op int32) (string) {
	switch op {
	case layers.ARPReply:
		return "🔵 ARP Reply"
	case layers.ARPRequest:
		return "🟢 ARP Request";
	default :
		return "🔴 Unknown ARP Operation";
	}

}
func Sniff_arp(){

	handle, err := pcap.OpenLive(device, snapShotLen, promiscuous, timeout);
	if err != nil {
		Exit_err(err);
	}
	defer handle.Close();

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType());

	for packet := range packetSource.Packets(){
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			if arp, ok := arpLayer.(*layers.ARP); ok {
				fmt.Println("⚡ ARP Detected ⚡");
				fmt.Printf("Sender MAC: %s\n", net.HardwareAddr(arp.SourceHwAddress));
				fmt.Printf("Sender IP: %s\n", net.IP(arp.SourceProtAddress));
				fmt.Printf("Target MAC: %s\n", net.HardwareAddr(arp.DstHwAddress));
				fmt.Printf("Target IP: %s\n", net.IP(arp.DstProtAddress));
				fmt.Printf("Arp Operation: %s\n", arp_operation(int32(arp.Operation)));
				fmt.Println("-------------------------------------------------")
			}

		}
	}
}
func Sniffing(){
	handle, err := pcap.OpenLive(device, snapShotLen, promiscuous, timeout);
	if err != nil {
		Exit_err(err);
	}
	defer handle.Close();

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType());

	for packet := range packetSource.Packets(){
		print_packet(packet);
	}
}
