package captureArp

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TODO: make a packet sender
// NOTE: So we just need to send arp replay to all devices in the LAN inorder to get mitm
// NOTE: So there is a type of arp messages that sent to all clients called Gratuitous which \
//       is using the ethernet layer dest mac address as broadcast address (ff:ff:ff:ff:ff:ff) \
//       to send the arp message to all client. Also the target mac in the arp message is broadcast too.
var (
	buffer gopacket.SerializableLayer
	option gopacket.SerializableLayer
)

func craft_arp(attackerMac []byte, targeMac []byte, getwayIp []byte, targetIp []byte, op uint16) *layers.ARP {
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         op,
		SourceHwAddress:   net.HardwareAddr(attackerMac), // Attacker mac
		SourceProtAddress: net.IPv4(getwayIp[0], getwayIp[1], getwayIp[2], getwayIp[3]), // default getway
		DstHwAddress:      net.HardwareAddr(targeMac), // target
		DstProtAddress:    net.IPv4(targetIp[0], targetIp[1], targetIp[2], targetIp[3]),
	}
	return arp
}

func craft_ethernet(targetHard []byte, attackerHard []byte) *layers.Ethernet {
	ether := &layers.Ethernet{
		EthernetType: layers.EthernetTypeARP,
		SrcMAC:       net.HardwareAddr(attackerHard),
		DstMAC:       net.HardwareAddr(targetHard),
	}
	return ether;
}

// TODO
func getTargetMac(targetIp []byte){

}
func Packet(handler *pcap.Handle) {
	// gopacket.SerializableLayer(buffer, option, &layers.Ethernet{}, &layers.ARP{})
    
}
