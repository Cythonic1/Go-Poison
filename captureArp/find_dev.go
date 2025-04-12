package captureArp

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket/pcap"
)

func Exit_err(err error){
	log.Fatal(err);
	os.Exit(1);
}
func print_addresses(addr pcap.Interface){
	for _, address := range addr.Addresses {
		fmt.Printf("\tIPv4: %s\n", address.IP);
		fmt.Printf("\tSub net mask: %s\n", address.Netmask);
	}
}
func Print_devices(devices[] pcap.Interface){
	for _, dev := range devices {
		fmt.Printf("device name : %s\n", dev.Name);
		fmt.Printf("device description : %s\n", dev.Description);
		fmt.Printf("device address: \n");
		print_addresses(dev);
		fmt.Printf("-------------------------------------------------\n");
	}
}


