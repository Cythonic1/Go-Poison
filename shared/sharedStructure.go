package shared

import "net"



type ParsedCommandLine struct {
	AttackerMAC    net.HardwareAddr
	VictimMAC      net.HardwareAddr
	VictimIP       net.IP
	DefaultGateway net.IP
}
