package main

import (
	"fmt"
	"net"
	"strings"
)

func parseIP(source string) string {
	if strings.Contains(source, ".") {
		// parse ipv4
		return strings.Split(source, ":")[0]
	}
	// parse ipv6
	if strings.Contains(source, "]") {
		return strings.Split(source, "]")[0][1:]
	}
	return source
}

func ParseSubnet(subnet string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subnet: %w", err)
	}
	return ipNet, nil
}

func IsIPInSubnets(ip string, ipNets []*net.IPNet) bool {
	for _, ipNet := range ipNets {
		if ipNet.Contains(net.ParseIP(ip)) {
			return true
		}
	}
	return false
}
