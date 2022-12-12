package safeurl

import (
	"fmt"
	"net"
)

// private CIDRs to ignore
var privateNetworks = []net.IPNet{
	// ipv4 sourced form https://www.rfc-editor.org/rfc/rfc5735
	parseCIDR("10.0.0.0/8"),         /* Private network - RFC 1918 */
	parseCIDR("172.16.0.0/12"),      /* Private network - RFC 1918 */
	parseCIDR("192.168.0.0/16"),     /* Private network - RFC 1918 */
	parseCIDR("127.0.0.0/8"),        /* Loopback - RFC 1122, Section 3.2.1.3 */
	parseCIDR("0.0.0.0/8"),          /* Current network (only valid as source address) - RFC 1122, Section 3.2.1.3 */
	parseCIDR("169.254.0.0/16"),     /* Link-local - RFC 3927 */
	parseCIDR("192.0.0.0/24"),       /* IETF Protocol Assignments - RFC 5736 */
	parseCIDR("192.0.2.0/24"),       /* TEST-NET-1, documentation and examples - RFC 5737 */
	parseCIDR("198.51.100.0/24"),    /* TEST-NET-2, documentation and examples - RFC 5737 */
	parseCIDR("203.0.113.0/24"),     /* TEST-NET-3, documentation and examples - RFC 5737 */
	parseCIDR("192.88.99.0/24"),     /* IPv6 to IPv4 relay (includes 2002::/16) - RFC 3068 */
	parseCIDR("198.18.0.0/15"),      /* Network benchmark tests - RFC 2544 */
	parseCIDR("224.0.0.0/4"),        /* IP multicast (former Class D network) - RFC 3171 */
	parseCIDR("240.0.0.0/4"),        /* Reserved (former Class E network) - RFC 1112, Section 4 */
	parseCIDR("255.255.255.255/32"), /* Broadcast - RFC 919, Section 7 */
	parseCIDR("100.64.0.0/10"),      /* Shared Address Space - RFC 6598 */
	// ipv6 sourced from https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
	parseCIDR("::/128"),        /* Unspecified Address - RFC 4291 */
	parseCIDR("::1/128"),       /* Loopback - RFC 4291 */
	parseCIDR("100::/64"),      /* Discard prefix - RFC 6666 */
	parseCIDR("2001::/23"),     /* IETF Protocol Assignments - RFC 2928 */
	parseCIDR("2001:2::/48"),   /* Benchmarking - RFC5180 */
	parseCIDR("2001:db8::/32"), /* Addresses used in documentation and example source code - RFC 3849 */
	parseCIDR("2001::/32"),     /* Teredo tunneling - RFC4380 - RFC8190 */
	parseCIDR("fc00::/7"),      /* Unique local address - RFC 4193 - RFC 8190 */
	parseCIDR("fe80::/10"),     /* Link-local address - RFC 4291 */
	parseCIDR("ff00::/8"),      /* Multicast - RFC 3513 */
	parseCIDR("2002::/16"),     /* 6to4 - RFC 3056 */
	parseCIDR("64:ff9b::/96"),  /* IPv4/IPv6 translation - RFC 6052 */
	parseCIDR("2001:10::/28"),  /* Deprecated (previously ORCHID) - RFC 4843 */
	parseCIDR("2001:20::/28"),  /* ORCHIDv2 - RFC7343 */
}

func parseCIDR(network string) net.IPNet {
	_, net, err := net.ParseCIDR(network)
	if err != nil {
		panic(fmt.Sprintf("error parsing %v: %v", network, err))
	}
	return *net
}

func parseIP(ip string) net.IP {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		panic(fmt.Sprintf("error parsing ip: %v", ip))
	}
	return parsed
}

func isIPBlocked(ip net.IP, blockedIPs []net.IP, blockedIPsCIDR []net.IPNet) bool {
	for _, blockedIP := range blockedIPs {
		if blockedIP.Equal(ip) {
			return true
		}
	}
	for _, blockedNet := range blockedIPsCIDR {
		if blockedNet.Contains(ip) {
			return true
		}
	}
	for _, net := range privateNetworks {
		if net.Contains(ip) {
			return true
		}
	}

	return false
}

func isIPAllowed(ip net.IP, allowedIPs []net.IP, allowedIPsCIDR []net.IPNet) bool {
	for _, allowedIP := range allowedIPs {
		if ip.Equal(allowedIP) {
			return true
		}
	}
	for _, allowedNet := range allowedIPsCIDR {
		if allowedNet.Contains(ip) {
			return true
		}
	}

	return false
}