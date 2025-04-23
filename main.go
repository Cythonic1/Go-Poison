package main

import (
	"arp_poision/captureArp"
	"log"
	"time"
	"fmt"
	"github.com/google/gopacket/pcap"
	"arp_poision/commandLineHandle"
	_ "arp_poision/utilites"
)

var (
	device string = "enp4s0"
	snapShotLen int32 = 1024
	promiscuous bool = false
	timeout time.Duration = 30 * time.Second
	handle *pcap.Handle
)

func main() {
	args := commandlinehandle.CommandLineArgsGen();
	fmt.Printf("[+] Parsed: %+v\n", args)

	// iface := utilites.Display_interfaces();
	handle, err := pcap.OpenLive(device, snapShotLen, promiscuous, timeout);
	if err != nil {
		log.Fatal("main func " ,err);
	}
	defer handle.Close();

	captureArp.Packet(handle, args);
	// captureArp.Sniff_arp()
}
