package captureArp

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TODO: make a packet sender
// NOTE : So we just need to send arp replay to all devices in the LAN inorder to get mitm
var (
	buffer gopacket.SerializableLayer;
	option gopacket.SerializableLayer;
)

func craft_arp(srcHard []byte, dstHard []byte, srcIP []byte, dstIP []byte, op uint16) (*layers.ARP){
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         op,
		SourceHwAddress:   net.HardwareAddr(srcHard),
		SourceProtAddress: net.IPv4(srcHard[0], srcHard[1], srcHard[2], srcHard[3]),
		DstHwAddress:      net.HardwareAddr(dstHard),
		DstProtAddress:    net.IPv4(dstIP[0], dstIP[1], dstIP[2], dstIP[3]),
	}
	return arp;
}

func craft_ethernet()
func Packet(handler *pcap.Handle){


	gopacket.SerializableLayer(buffer, option, &layers.Ethernet{}, &layers.ARP{});

}
