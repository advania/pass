package helpers

import (
	"net"
)

func ParseCIDR(cidr string) (network *net.IPNet, err error) {
	if _, network, err = net.ParseCIDR(cidr); err == nil {
		return network, err
	}

	return network, err
}

func StringArrayToIPNet(s []string) (nets []*net.IPNet, err error) {
	for i := range s {
		if n, err := ParseCIDR(s[i]); err == nil {
			nets = append(nets, n)
		} else {
			return nets, err
		}
	}

	return nets, err
}

func IpNetArrayContainsIP(arr []*net.IPNet, ip net.IP) (found bool) {
	for subnet := range arr {
		if arr[subnet].Contains(ip) {
			return true
		}
	}

	return found
}
