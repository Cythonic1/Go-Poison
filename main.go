// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Pythonic01
package main

import (
	commandlinehandle "arp_poision/commandLineHandle"
	"arp_poision/utilites"
	"log"
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

	if os.Geteuid() != 0 {
		log.Fatal(": Run the program as root");
	}

	iface := utilites.Display_interfaces()

	handle, err := pcap.OpenLive(iface.Name, snapShotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal("main func ", err)
	}
	defer handle.Close()

	args := os.Args;
	commandlinehandle.CommandLineChecker(args, handle, iface);
}
