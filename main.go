package main

import (
	"arp_poision/captureArp"
	"log"
	"time"
	"github.com/google/gopacket/pcap"
)

var (
	device string = "enp4s0"
	snapShotLen int32 = 1024
	promiscuous bool = false
	timeout time.Duration = 30 * time.Second
	handle *pcap.Handle
)
func main() {
	handle, err := pcap.OpenLive(device, snapShotLen, promiscuous, timeout);
	if err != nil {
		log.Fatal("main func " ,err);
	}
	defer handle.Close();

	captureArp.Packet(handle);
	// captureArp.Sniff_arp()
}
