package helpers

import (
	"net"
)

// StringArrayToIPNet parses an array of string using ParseCIDR, returns array of *net.IPNet and error
func StringArrayToIPNet(s []string) (nets []*net.IPNet, err error) {
	for i := range s {
		var n *net.IPNet
		if _, n, err = net.ParseCIDR(s[i]); err != nil {
			return nil, err
		}

		nets = append(nets, n)
	}

	return nets, err
}

// IPNetArrayContainsIP checks if an array of *net.IPNet contains the given net.IP, returns bool
func IPNetArrayContainsIP(arr []*net.IPNet, ip net.IP) bool {
	for subnet := range arr {
		if arr[subnet].Contains(ip) {
			return true
		}
	}

	return false
}
