package helpers

import (
	"net"
	"testing"
)

func genTestNets() map[string]string {
	tests := map[string]string {
		"0.0.0.0/0": "0.0.0.0/0",
		"255.255.255.255/0": "0.0.0.0/0",
		"255.255.255.255/32": "255.255.255.255/32",
		"192.0.2.0/24": "192.0.2.0/24",
		"192.0.2.42/24": "192.0.2.0/24",
		"192.0.2.0/31": "192.0.2.0/31",
		"192.0.2.0/32": "192.0.2.0/32",
		"192.0.2.0/33": "invalid CIDR address: 192.0.2.0/33",
		"198.51.100.0/24": "198.51.100.0/24",
		"198.51.100.0/31": "198.51.100.0/31",
		"198.51.100.0/32": "198.51.100.0/32",
		"198.51.100.0/33": "invalid CIDR address: 198.51.100.0/33",
		"::1/128": "::1/128",
		"0000:0000:0000:0000:0000:0000:0000:0001/128": "::1/128",
		"::0000:0000:0000:0000:0000:0000:0001/128": "::1/128",
		"::0000:0000:0000:0000:0000:0001/128": "::1/128",
		"::0000:0000:0000:0000:0001/128": "::1/128",
		"::0000:0000:0000:0001/128": "::1/128",
		"::0000:0000:0001/128": "::1/128",
		"::0000:0001/128": "::1/128",
		"::0001/128": "::1/128",
		"2001:db8::/32": "2001:db8::/32",
		"2001:db8::0::/32": "invalid CIDR address: 2001:db8::0::/32",
		"2001:db8::1337/32": "2001:db8::/32",
		"2001:db8:0:0:1:2:3:4/48": "2001:db8::/48",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0": "::/0",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
		"2001:db8::/129": "invalid CIDR address: 2001:db8::/129",
		"a::/1": "::/1",
		"a:/1": "invalid CIDR address: a:/1",
		"a/1": "invalid CIDR address: a/1",
	}

	return tests
}

func TestParseCIDR(t *testing.T) {
	tests := genTestNets()

	for cidr, expected := range tests {
		if result, err := ParseCIDR(cidr); !(err == nil && result.String() == expected) {
			if err == nil && result.String() != expected {
				t.Errorf("ParseCIDR(\"%s\") should be \"%s\" but is \"%s\"\n", cidr, expected, result)
			} else if err != nil && err.Error() != expected {
				t.Errorf("ParseCIDR(\"%s\") should be \"%s\" but is \"%s\"\n", cidr, expected, err.Error())
			}
		}
	}
}

// 2018-09-19 / GG -- BenchmarkParseCIDR-8   	10000000	       208 ns/op
func BenchmarkParseCIDR(b *testing.B) {
	net := "2001:db8:0:0:1:2:3:4/48"

	for n := 0; n < b.N; n++ {
		ParseCIDR(net)
	}
}

func TestStringArrayToIPNet(t *testing.T) {
	tests := genTestNets()

	for n, expected := range tests {
		nArr := []string{
			n,
		}

		result, resultErr := StringArrayToIPNet(nArr)

		if resultErr != nil && resultErr.Error() != expected {
			t.Fatalf("netpErr is \"%s\" but should be \"%s\"", resultErr.Error(), expected)
		} else if resultErr == nil && len(result) != 1 {
			t.Fatalf("for %s len(result) is %d but should be 1", n, len(result))
		} else if resultErr == nil && result[0].String() != expected {
			t.Fatalf("result[0] is \"%s\" but should be \"%s\"", result[0], expected)
		}
	}
}

// 2018-09-19 / GG -- BenchmarkStringArrayToIPNet-8   	  300000	      5340 ns/op
func BenchmarkStringArrayToIPNet(b *testing.B) {
	tests := genTestNets()
	var tests_ []string

	for n, _ := range tests {
		if _, err := ParseCIDR(n); err == nil {
			tests_ = append(tests_, n)
		}
	}

	for n := 0; n < b.N; n++ {
		StringArrayToIPNet(tests_)
	}
}

func TestIpNetArrayContainsIP(t *testing.T) {
	tests := genTestNets()

	for n, _ := range tests {
		if n, err := ParseCIDR(n); err == nil {
			nArr := []*net.IPNet {
				n,
			}
			if result := IpNetArrayContainsIP(nArr, n.IP); result != true {
				t.Errorf("IpNetArrayContainsIP(\"%s\") should be \"%s\" but is \"%s\"\n", n, true, false)
			}
		}
	}

	// todo test failures
}

func BenchmarkIpNetArrayContainsIP(b *testing.B) {
	//TODO
}
