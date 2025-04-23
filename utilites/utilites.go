package utilites

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket/pcap"
)


func Display_interfaces() string{
	var iface int;
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("Error while listing interfaces");
	}
	fmt.Println("🌐 Available Network Interfaces:")
	Print_devices(interfaces);
	fmt.Printf("Enter interface ID:");
	fmt.Scanln(&iface);

	fmt.Printf("The interface u chose is %s\n", interfaces[iface].Name)
	return interfaces[iface].Name
}

func print_addresses(addr pcap.Interface){
	for _, address := range addr.Addresses {
		fmt.Printf("\tIPv4: %s\n", address.IP);
		fmt.Printf("\tSubnet Mask: %s\n", net.IP(address.Netmask).String())
	}
}
func Print_devices(devices[] pcap.Interface){
	for i, dev := range devices {
		fmt.Printf("ID: %d\n",i )
		fmt.Printf("device name : %s\n", dev.Name);
		fmt.Printf("device description : %s\n", dev.Description);
		fmt.Printf("device address: \n");
		print_addresses(dev);
		fmt.Printf("-------------------------------------------------\n");
	}
}


