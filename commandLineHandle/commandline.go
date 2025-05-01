package commandlinehandle

import (
	"arp_poision/captureArp"
	"arp_poision/shared"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
)

type CommandLineArgs struct {
	AttackerMAC    string
	AttackerIP     string
	VictimMAC      string
	VictimIP       string
	DefaultGateway string
}




func help_menu(programName string) {
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                        🦍 Jungle Packet Tool - Help Menu                   ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Usage: ./%-25s [dynamic | static]                                ║\n", programName)
	fmt.Println("║                                                                            ║")
	fmt.Println("║ Modes:                                                                     ║")
	fmt.Println("║  dynamic               Perform automatic discovery (no additional flags)   ║")
	fmt.Println("║  static                Requires manual input of all the flags below        ║")
	fmt.Println("║                                                                            ║")
	fmt.Println("║ Required Flags for 'static' mode:                                          ║")
	fmt.Println("║  -amac <MAC>           Attacker's MAC address                              ║")
	fmt.Println("║  -vmac <MAC>           Victim's MAC address                                ║")
	fmt.Println("║  -vip <IP>             Victim's IP address                                 ║")
	fmt.Println("║  -dip <IP>             Default gateway IP address                          ║")
	fmt.Println("║                                                                            ║")
	fmt.Println("║ General Flags:                                                             ║")
	fmt.Println("║  -h, --help            Show this help menu                                 ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
}


func contains(arr []string, item string) bool {
	return slices.Contains(arr, item);
}

// add Interface name
func checkStatic(args []string) {

	var user_command CommandLineArgs;
	requiredFlags := []string{"-amac", "-vmac", "-vip", "-dip"}

	for _, flag := range requiredFlags {
		if !contains(args, flag) {
			log.Fatalf("Missing argument: %s", flag)
			help_menu(args[0])
		}
	}

	for i, data := range args{
		if data == "-amac" {
			user_command.AttackerMAC = args[i+1];
		}

		if data == "-vmac" {
			user_command.VictimMAC = args[i+1];
		}

		if data == "-vip" {
			user_command.VictimIP = args[i+1];
		}
		if data == "-dip" {
			user_command.DefaultGateway = args[i+1];
		}

	}
	fmt.Println("commands ", user_command);
	CommandLineArgsGen(user_command);
}

func checkDynamic(handler *pcap.Handle , iface net.Interface) {
	var user_command CommandLineArgs;
	var targets []*captureArp.Target;

	ch := make(chan string);

	addr , err := iface.Addrs();
	if err != nil {
		log.Fatal("Error finding device IP");
	}
	user_command.AttackerIP = addr[0].String()
	user_command.AttackerMAC = iface.HardwareAddr.String()
	println(user_command.AttackerIP);

	// Then we want to discover devices inorder to fill up the rest

	atp := addr[0].(*net.IPNet);

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		captureArp.Sniff_arp(atp.IP.To4(), ch, &targets)
	}()

	time.Sleep(3 * time.Second);
	go func(){
		defer wg.Done()
		captureArp.Discover_devices(handler,iface.HardwareAddr , atp.IP.To4(), ch);
	}()
	wg.Wait()
	target_index := print_targets(targets);

	user_command.DefaultGateway = "192.168.0.1";
	user_command.VictimMAC = targets[target_index].TargetMac.String();
	user_command.VictimIP = targets[target_index].TargetIp.String();

	fmt.Println("User command Structure look like this ", user_command);

	something := CommandLineArgsGen(user_command);

	fmt.Println("User command after parsing ", something);
	captureArp.Packet_poison(handler, something)



}

func print_targets (targets []*captureArp.Target) int {
	if len(targets) == 0 {
		log.Fatal("No device detected");
	}
	var target_index int;
	fmt.Println("Targets Found 🖥️");
	for i, target := range targets {
		fmt.Printf("Target ID: %d\n", i);
		fmt.Printf("Target IP : %s\n", target.TargetIp.String() );
		fmt.Printf("Target MAC: %s\n", target.TargetMac.String());
		println("--------------------------------------------");
	}
	fmt.Printf("Enter the target ID u want to attacke: ");
	fmt.Scanln(&target_index);
	return target_index;


	
}

func CommandLineChecker(args []string, handler *pcap.Handle, iface net.Interface) {


	if args[1] != "dynamic" && args[1] != "static" {
		help_menu(args[0]);
		os.Exit(1);
	}

	mode := args[1];
	switch mode {
	case "static":
		checkStatic(args[2:])

	case "dynamic":
		checkDynamic(handler, iface);
	default:
		help_menu(args[0])
		os.Exit(1);
	}

}
func CommandLineArgsGen(args CommandLineArgs) shared.ParsedCommandLine {
	var parsed shared.ParsedCommandLine



	fmt.Printf("[+] Parsed: %+v\n", args)

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
	parsed.DefaultGateway = Dip.To4()

	Vip := net.ParseIP(args.VictimIP)
	if Vip == nil {
		log.Fatal("Error: Ip address is not valid")
	}
	parsed.VictimIP = Vip.To4()
	return parsed
}
