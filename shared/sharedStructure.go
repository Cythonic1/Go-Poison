
// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Pythonic01
package shared

import "net"



type ParsedCommandLine struct {
	AttackerMAC    net.HardwareAddr
	VictimMAC      net.HardwareAddr
	VictimIP       net.IP
	DefaultGateway net.IP
}
