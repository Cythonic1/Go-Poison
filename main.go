package main

import (
	commandlinehandle "arp_poision/commandLineHandle"
	"arp_poision/utilites"
	"log"
	"net"
	"os"
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

	iface := utilites.Display_interfaces()

	handle, err := pcap.OpenLive(iface.Name, snapShotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal("main func ", err)
	}
	defer handle.Close()
	var args commandlinehandle.ParsedCommandLine
	// args := commandlinehandle.CommandLineArgsGen();
	asrgs := os.Args;
	commandlinehandle.CommandLineChecker(asrgs, handle);
	ch := make(chan string);


	// Attacker IP
	// args.DefaultGateway = iface.Addresses[0].IP.To4()

	// Attacker MAC
	mac, err := net.ParseMAC("f4:b5:20:53:5f:59")
	if err != nil {
		log.Fatal("Parsing attacker mac")
	}
	args.AttackerMAC = mac


	// Prepare wait group
	close(ch);

}
