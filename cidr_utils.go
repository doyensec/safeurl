package safeurl

import (
	"log"
	"net"
)

func GetIPsInCIRDRange(cidr string) []string {
	var result []string

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatal(err)
	}
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); increment(ip) {
		result = append(result, ip.String())
	}

	return result
}

func increment(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
