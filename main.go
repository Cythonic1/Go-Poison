package main

import (
	"arp_poision/captureArp"
	commandlinehandle "arp_poision/commandLineHandle"
	"arp_poision/utilites"
	_ "arp_poision/utilites"
	"fmt"
	"log"
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
	args := commandlinehandle.CommandLineArgsGen()
	fmt.Printf("[+] Parsed: %+v\n", args)

	iface := utilites.Display_interfaces()
	handle, err := pcap.OpenLive(iface, snapShotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal("main func ", err)
	}
	defer handle.Close()

	captureArp.Packet(handle, args)
	// captureArp.Sniff_arp()
}
