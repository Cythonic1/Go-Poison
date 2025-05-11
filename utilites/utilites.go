
// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Pythonic01

package utilites

import (
	"fmt"
	"log"
	"net"

)


func Display_interfaces() net.Interface{
	var iface int;
	interfaces, err := net.Interfaces();
	if err != nil {
		log.Fatal("Error while listing interfaces");
	}
	fmt.Println("🌐 Available Network Interfaces:")
	print_devices(interfaces);
	fmt.Printf("Enter interface ID:");
	fmt.Scanln(&iface);

	fmt.Printf("The interface u chose is %s\n", interfaces[iface].Name)
	return interfaces[iface]
}

func print_addresses(addrs []net.Addr) {
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		mask := ipNet.Mask

		if ip.To4() != nil {
			fmt.Printf("\tIPv4: %s\n", ip.String())
			fmt.Printf("\tSubnet Mask: %s\n", net.IP(mask).String())
		}
	}
}

func print_devices(devices []net.Interface) {
	for i, dev := range devices {
		fmt.Printf("ID: %d\n", i)
		fmt.Printf("Device Name: %s\n", dev.Name)
		fmt.Printf("Hardware Addr (MAC): %s\n", dev.HardwareAddr.String())

		addrs, err := dev.Addrs()
		if err != nil {
			log.Printf("🛑 Error getting addresses for %s: %v\n", dev.Name, err)
			continue
		}

		fmt.Println("Device Addresses:")
		print_addresses(addrs)
		fmt.Println("-------------------------------------------------")
	}
}


