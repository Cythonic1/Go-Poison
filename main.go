package main

import (
	"arp_poision/captureArp"
	commandlinehandle "arp_poision/commandLineHandle"
	"arp_poision/utilites"
	_ "fmt"
	"log"
	"net"
	"sync"
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
	var args commandlinehandle.ParsedCommandLine

	iface := utilites.Display_interfaces()

	// Attacker IP
	args.DefaultGateway = iface.Addresses[0].IP.To4()

	// Attacker MAC
	mac, err := net.ParseMAC("f4:b5:20:53:5f:59")
	if err != nil {
		log.Fatal("Parsing attacker mac")
	}
	args.AttackerMAC = mac

	handle, err := pcap.OpenLive(iface.Name, snapShotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal("main func ", err)
	}
	defer handle.Close()

	// Prepare wait group
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		captureArp.Sniff_arp(args.DefaultGateway)
	}()

	time.Sleep(5 * time.Second);
	go captureArp.Discover_devices(handle, args, args.DefaultGateway)

	wg.Wait()
}
