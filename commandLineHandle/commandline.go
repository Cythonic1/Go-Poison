package commandlinehandle

import (
	"flag"
	"net"
	"regexp"
	"fmt"
)
type CommandLineArgs struct {
	AttackerMAC    string
	VictimMAC      string
	VictimIP       string
	DefaultGateway string
}


// TODO: Rename the command line argumet make them easier
func CommandLineArgsGen() CommandLineArgs {
	var args CommandLineArgs

	flag.StringVar(&args.AttackerMAC, "attacker-mac", "", "Attacker's MAC address (e.g., 00:11:22:33:44:55)")
	flag.StringVar(&args.VictimMAC, "victim-mac", "", "Victim's MAC address")
	flag.StringVar(&args.VictimIP, "victim-ip", "", "Victim's IP address")
	flag.StringVar(&args.DefaultGateway, "gateway", "", "Default gateway IP address")

	flag.Parse()

	validateMAC := func(mac string) bool {
		match, _ := regexp.MatchString(`^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$`, mac)
		return match
	}

	if !validateMAC(args.AttackerMAC) || !validateMAC(args.VictimMAC) {
		fmt.Println("[-] Invalid MAC address format.")
	}

	if net.ParseIP(args.VictimIP) == nil || net.ParseIP(args.DefaultGateway) == nil {
		fmt.Println("[-] Invalid IP address format.")
	}

	return args
}

