package commandlinehandle

import (
	"flag"
	"fmt"
	"log"
	"net"
)

type CommandLineArgs struct {
	AttackerMAC    string
	VictimMAC      string
	VictimIP       string
	DefaultGateway string
}

type ParsedCommandLine struct {
	AttackerMAC    net.HardwareAddr
	VictimMAC      net.HardwareAddr
	VictimIP       net.IP
	DefaultGateway net.IP
}

func CommandLineArgsGen() ParsedCommandLine {
	var args CommandLineArgs
	var parsed ParsedCommandLine

	flag.StringVar(&args.AttackerMAC, "amac", "", "Attacker's MAC address (e.g., 00:11:22:33:44:55)")
	flag.StringVar(&args.VictimMAC, "vmac", "", "Victim's MAC address")
	flag.StringVar(&args.VictimIP, "vip", "", "Victim's IP address")
	flag.StringVar(&args.DefaultGateway, "dip", "", "Default gateway IP address")

	fmt.Printf("[+] Parsed: %+v\n", args)
	flag.Parse()

	Amac, err := net.ParseMAC(args.AttackerMAC)
	if err != nil {
		log.Fatal("Error: ", err)
	}
	parsed.AttackerMAC = Amac

	Vmac, err := net.ParseMAC(args.VictimMAC)
	if err != nil {
		log.Fatal("Error: ", err)
	}
	parsed.VictimMAC = Vmac

	Dip := net.ParseIP(args.DefaultGateway)
	if Dip == nil {
		log.Fatal("Error: Ip address is not valid")
	}
	parsed.DefaultGateway = Dip

	Vip := net.ParseIP(args.VictimIP)
	if Vip == nil {
		log.Fatal("Error: Ip address is not valid")
	}
	parsed.VictimIP = Vip
	return parsed
}
