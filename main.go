package main

import (
	"arp_poision/captureArp"
	commandlinehandle "arp_poision/commandLineHandle"
	"arp_poision/utilites"
	_ "fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket/pcap"
)

var (
	device      string        = "enp4s0"
	snapShotLen int32         = 1024
	promiscuous bool          = false
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
)

func main() {
	// args := commandlinehandle.CommandLineArgsGen()
	// fmt.Printf("[+] Parsed: %+v\n", args)

	var args commandlinehandle.ParsedCommandLine;

	iface := utilites.Display_interfaces()
	// NOTE: This represent the attacker IP at the moment
	args.DefaultGateway = iface.Addresses[0].IP.To4();
	mac , err := net.ParseMAC("f4:b5:20:53:5f:59");
	if err != nil {
		log.Fatal("Parsing attacker mac");
	}
	args.AttackerMAC = mac;
	handle, err := pcap.OpenLive(iface.Name, snapShotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal("main func ", err)
	}
	
	go captureArp.Sniff_arp(args.DefaultGateway)
	go captureArp.Discover_devices(handle , args , args.DefaultGateway );
	defer handle.Close()

	// captureArp.Packet_poison(handle, args)
	// captureArp.Sniff_arp()
}
