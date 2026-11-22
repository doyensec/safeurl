package safeurl

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
)

func TestBlockedIP(t *testing.T) {
	cfg := GetConfigBuilder().
		EnableIPv6(true).
		Build()

	client := Client(cfg)

	ips := []string{"127.0.0.1", "[::1]",
		// decimal
		"2130706433", "3232235777",
		// octal
		"017700000001:80/",
		// hexadecimal
		"0x7f000001", "0xc0a80014", "0x0000007f.0x00000000.0x00000000.0x00000001", "0x7f.0x0.0x00000000.0x01",
		// malformed - uncommon format
		"[::]:80", "0/", "127.1", "0177.0x0.0x0.0x1", "0.0.0.0", "127.127.127.127",
		// ipv4-mapped IPv6
		"[::ffff:192.0.2.1]",
		// ipv6
		"[::]:80", "[0000::1]:80", "[::1]/server-status",
		// ipv6 -> 169.254.169.254 translation (nat64 local-use prefix)
		"[64:ff9b:1::a9fe:a9fe]",
		// segment routing
		"[5f00:5aa9:e79f:8940:a51a:be61:ef3b:bab9]",
		// documentation
		"[3fff:4e1:6fb3:f8a2:7948:ff06:258:486]",
		// ipv6 dummy prefix
		"[100::1:a442:286a:836e:da87]",
		// azure wireserver (public address, platform-internal on azure vms)
		"168.63.129.16", "[::ffff:168.63.129.16]",
	}

	for _, ip := range ips {
		_, err := client.Get(fmt.Sprintf("http://%v", ip))
		if err == nil {
			t.Errorf("ip: %v not blocked. client did not return error", ip)
		}
		err = unwrap(err)
		_, ok := err.(*AllowedIPError)
		if !ok {
			t.Errorf("client returned incorrect error: %v", err)
		}
	}
}

func TestTLSConfig(t *testing.T) {
	tls_config := &tls.Config{
		InsecureSkipVerify: true,
	}
	cfg := GetConfigBuilder().SetTlsConfig(tls_config).Build()
	client := Client(cfg)

	_, err := client.Get("https://expired.badssl.com/")
	if err != nil {
		t.Errorf("Failed to make insecure connection %v", err)
	}

}

func TestTransport(t *testing.T) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	cfg := GetConfigBuilder().SetTransport(transport).Build()
	client := Client(cfg)

	_, err := client.Get("https://expired.badssl.com/")
	if err != nil {
		t.Errorf("Failed to make insecure connection %v", err)
	}

}

func TestTransportAndTLSConfig(t *testing.T) {
	cfg := GetConfigBuilder().
		SetTransport(&http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		}).
		SetTlsConfig(&tls.Config{
			InsecureSkipVerify: true,
		}).
		Build()

	client := Client(cfg)

	_, err := client.Get("https://expired.badssl.com/")
	if err != nil {
		t.Errorf("Failed to make insecure connection %v", err)
	}

}

func TestBlockCIDRRange(t *testing.T) {
	cfg := GetConfigBuilder().Build()
	client := Client(cfg)

	ips := GetIPsInCIRDRange("192.168.0.0/28")

	for _, ip := range ips {
		_, err := client.Get(fmt.Sprintf("http://%v", ip))
		if err == nil {
			t.Errorf("ip: %v not blocked. client did not return error", ip)
		}
		err = unwrap(err)
		_, ok := err.(*AllowedIPError)
		if !ok {
			t.Errorf("client return incorrect error: %v", err)
		}
	}
}

func TestUserSuppliedIPBlock(t *testing.T) {
	ips := []string{}

	cfg := GetConfigBuilder().
		SetBlockedIPs("127.0.0.1").
		Build()

	client := Client(cfg)

	for _, ip := range ips {
		_, err := client.Get(fmt.Sprintf("http://%v", ip))
		if err == nil {
			t.Errorf("ip: %v not blocked. request did not return error", ip)
		}
		err = unwrap(err)
		_, ok := err.(*AllowedIPError)
		if !ok {
			t.Errorf("client return incorrect error: %v", err)
		}
	}
}

func TestBlockedPort(t *testing.T) {
	port := 8080

	cfg := GetConfigBuilder().
		SetBlockedIPs().
		SetAllowedPorts(port).
		Build()

	client := Client(cfg)

	_, err := client.Get(fmt.Sprintf("http://%v:%v", "127.0.0.1", port+1))
	if err == nil {
		t.Errorf("port: %v not blocked. request did not return error", port)
	}
	err = unwrap(err)
	_, ok := err.(*AllowedPortError)
	if !ok {
		t.Errorf("client returned incorrect error: %v", err)
	}
}

func TestAllowedPort(t *testing.T) {
	port := 8080

	cfg := GetConfigBuilder().
		SetAllowedIPs("127.0.0.1").
		SetAllowedPorts(port).
		Build()

	client := Client(cfg)

	_, err := client.Get(fmt.Sprintf("http://%v:%v", "127.0.0.1", port))
	if err != nil {
		t.Errorf("port: %v blocked. client returned error: %v", port, err)
	}
}

func TestAllowedHost(t *testing.T) {
	host := "service.test"

	cfg := GetConfigBuilder().
		SetAllowedIPs("127.0.0.1").
		SetAllowedPorts(8080).
		SetAllowedHosts(host).
		EnableTestMode(true).
		Build()

	client := Client(cfg)

	_, err := client.Get(fmt.Sprintf("http://%v:8080", host))
	if err != nil {
		t.Errorf("host: %v blocked. client returned error: %v", host, err)
	}
}

func TestBlockedHost(t *testing.T) {
	host := "service.test"

	cfg := GetConfigBuilder().
		SetAllowedHosts("x" + host).
		Build()

	client := Client(cfg)

	_, err := client.Get(fmt.Sprintf("http://%v", host))
	if err == nil {
		t.Errorf("host: %v not blocked. client did not return an error", host)
	}
	err = unwrap(err)
	_, ok := err.(*AllowedHostError)
	if !ok {
		t.Errorf("client return incorrect error: %v", err)
	}
}

func TestAllowedScheme(t *testing.T) {
	scheme := "http"
	host := "service.test"

	cfg := GetConfigBuilder().
		SetAllowedPorts(8080).
		SetAllowedSchemes(scheme).
		SetAllowedHosts(host).
		SetAllowedIPs("127.0.0.1").
		EnableTestMode(true).
		Build()

	client := Client(cfg)

	_, err := client.Get(fmt.Sprintf("%v://%v:8080", scheme, host))
	if err != nil {
		t.Errorf("scheme: %v blocked. client returned error: %v", scheme, err)
	}
}

func TestBlockedScheme(t *testing.T) {
	scheme := "http"
	host := "service.test"

	cfg := GetConfigBuilder().
		SetAllowedSchemes("ftp").
		SetAllowedHosts(host).
		Build()

	client := Client(cfg)

	_, err := client.Get(fmt.Sprintf("%v://%v", scheme, host))
	if err == nil {
		t.Errorf("scheme: %v not blocked. client did not return an error", host)
	}
	err = unwrap(err)
	_, ok := err.(*AllowedSchemeError)
	if !ok {
		t.Errorf("client returned incorrect error: %v", err)
	}
}

func TestDNSRebinding(t *testing.T) {
	cfg := GetConfigBuilder().
		SetAllowedSchemes("http").
		SetAllowedHosts("service-rbnd.test").
		SetAllowedPorts(8080).
		EnableTestMode(true).
		Build()

	client := Client(cfg)

	_, err := client.Get("http://service-rbnd.test:8080")
	if err == nil {
		t.Errorf("client did not return error: %v", err)
	}
	err = unwrap(err)
	_, ok := err.(*AllowedIPError)
	if !ok {
		t.Errorf("client returned incorrect error: %v", err)
	}
}

func TestDisabledIPv6(t *testing.T) {
	cfg := GetConfigBuilder().
		SetAllowedSchemes("http").
		SetAllowedHosts("service6.test").
		SetAllowedIPs("::1").
		SetAllowedPorts(8080).
		EnableIPv6(false).
		EnableTestMode(true).
		Build()

	client := Client(cfg)

	_, err := client.Get("http://service6.test:8080")
	if err == nil {
		t.Errorf("ipv6 not blocked. client did not return error")
	}
	err = unwrap(err)
	_, ok := err.(*IPv6BlockedError)
	if !ok {
		t.Errorf("client returned incorrect error: %v", err)
	}
}

func TestBlockedSendingCredentials(t *testing.T) {
	cfg := GetConfigBuilder().
		SetAllowedSchemes("http").
		SetAllowedHosts("service.test").
		SetAllowedIPs("127.0.0.1").
		SetAllowedPorts(8080).
		EnableTestMode(true).
		AllowSendingCredentials(false).
		Build()

	client := Client(cfg)

	creds := []string{"user:pass", "u:pass", "user:p"}

	for _, c := range creds {
		_, err := client.Get(fmt.Sprintf("http://%v@service.test:8080", c))
		if err == nil {
			t.Errorf("sending credentials not blocked. client did not return error")
		}
		err = unwrap(err)
		_, ok := err.(*SendingCredentialsBlockedError)
		if !ok {
			t.Errorf("client returned incorrect error: %v", err)
		}
	}
}

func TestIPsInBlockedCIDRAreBlocked(t *testing.T) {
	cfg := GetConfigBuilder().
		SetBlockedIPsCIDR("34.210.62.0/25", "216.239.34.0/25").
		Build()

	client := Client(cfg)

	twoIpInBlockedCIDR := []string{"34.210.62.107", "216.239.34.21"}

	for _, ipInBlockedCIDR := range twoIpInBlockedCIDR {
		_, err := client.Get(fmt.Sprintf("http://%v", ipInBlockedCIDR))
		if err == nil {
			t.Errorf("IP in custom CIDR blocklist not blocked. client did not return error")
		}
		err = unwrap(err)
		_, ok := err.(*AllowedIPError)
		if !ok {
			t.Errorf("client returned incorrect error: %v", err)
		}
	}
}

func TestIPsOutsideBlockedCIDRAreNotBlocked(t *testing.T) {
	cfg := GetConfigBuilder().
		SetBlockedIPsCIDR("34.210.62.0/25", "216.239.34.0/25").
		Build()

	client := Client(cfg)

	twoIpInBlockedCIDR := []string{"1.1.1.1"} // generic external IP - this may not resolve in the future

	for _, ipInBlockedCIDR := range twoIpInBlockedCIDR {
		_, err := client.Get(fmt.Sprintf("http://%v", ipInBlockedCIDR))

		if err != nil {
			t.Errorf("IP outside CIDR blocklist is blocked.")

			err = unwrap(err)
			_, ok := err.(*AllowedIPError)
			if !ok {
				t.Errorf("client returned incorrect error: %v", err)
			}
		}
	}
}
func TestMultipleIPsInBlockedCIDRAreBlocked(t *testing.T) {
	cfg := GetConfigBuilder().
		EnableTestMode(true).
		SetBlockedIPsCIDR("34.210.62.0/25").
		Build()

	client := Client(cfg)

	ipsInBlockedCIDR := GetIPsInCIRDRange("34.210.62.0/25")

	for _, singleInCIDR := range ipsInBlockedCIDR {

		_, err := client.Get(fmt.Sprintf("http://%v", singleInCIDR))
		if err == nil {
			t.Errorf("IP in custom CIDR blocklist not blocked. client did not return error")
		}
		err = unwrap(err)
		_, ok := err.(*AllowedIPError)
		if !ok {
			t.Errorf("client returned incorrect error: %v", err)
		}
	}
}

func TestIPInAllowedCIDRIsAllowed(t *testing.T) {
	cfg := GetConfigBuilder().
		// EnableTestMode(true).
		SetAllowedIPsCIDR("34.210.62.0/25").
		Build()

	client := Client(cfg)

	ipInAllowedCIDR := "34.210.62.107"

	_, err := client.Get(fmt.Sprintf("http://%v", ipInAllowedCIDR))
	if err != nil {
		t.Errorf("IP in CIDR allowlist was blocked.")
		err = unwrap(err)
		_, ok := err.(*AllowedIPError)
		if !ok {
			t.Errorf("client returned incorrect error: %v", err)
		}
	}

}

func TestIPOutsideAllowedCIDRisBlocked(t *testing.T) {
	cfg := GetConfigBuilder().
		SetAllowedIPsCIDR("34.210.62.0/25").
		Build()

	client := Client(cfg)

	ipOutsideAllowedCIDR := "172.217.14.195"

	_, err := client.Get(fmt.Sprintf("http://%v", ipOutsideAllowedCIDR))
	if err == nil {
		t.Errorf("IP outside custom CIDR allowlist not blocked. client did not return error")
	}
	err = unwrap(err)
	_, ok := err.(*AllowedIPError)
	if !ok {
		t.Errorf("client returned incorrect error: %v", err)
	}

}

func TestAllowedIPInBlockedCIDRIsAllowed(t *testing.T) {
	cfg := GetConfigBuilder().
		SetBlockedIPsCIDR("34.210.62.0/25").
		SetAllowedIPs("34.210.62.107").
		Build()

	client := Client(cfg)

	allowdIpInsideBlockedCIDR := "34.210.62.107"

	_, err := client.Get(fmt.Sprintf("http://%v", allowdIpInsideBlockedCIDR))
	if err != nil {
		t.Errorf("Allowlisted IP in a blockedCIDR was blocked. client did not return error")
		t.Errorf("client returned incorrect error: %v", err)
	}

}

func TestInternalIPAreAlwaysBlocked(t *testing.T) {
	cfg := GetConfigBuilder().
		SetBlockedIPsCIDR("34.210.62.0/25").
		SetAllowedIPs("34.210.62.107").
		SetAllowedPorts(8080).
		Build()

	client := Client(cfg)

	internalIPShouldBeBlocked := "127.0.0.1:8080"

	_, err := client.Get(fmt.Sprintf("http://%v", internalIPShouldBeBlocked))
	if err == nil {
		t.Errorf("Internal IP was not blocked. client did not return error")
	}

	err = unwrap(err)
	_, ok := err.(*AllowedIPError)
	if !ok {
		t.Errorf("client returned incorrect error: %v", err)
	}

}

func TestInvalidHostValidation(t *testing.T) {
	cfg := GetConfigBuilder().Build()
	client := Client(cfg)

	urls := []string{"http://[]", "http://[]:123", "http://:123"}

	for _, url := range urls {
		_, err := client.Get(url)
		if err == nil {
			t.Errorf("invalid host from url => %v was accepted. client didn't not return an error", err)
		}

		err = unwrap(err)
		_, ok := err.(*InvalidHostError)
		if !ok {
			t.Errorf("client returned incorrect error: %v", err)
		}
	}

}

func TestConfigTransportWithCustomDialPanics(t *testing.T) {
	cases := []struct {
		name      string
		transport *http.Transport
	}{
		{
			name: "DialTLSContext",
			transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return nil, fmt.Errorf("should never be called")
				},
			},
		},
		{
			name: "DialTLS",
			transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialTLS: func(network, addr string) (net.Conn, error) {
					return nil, fmt.Errorf("should never be called")
				},
			},
		},
		{
			name: "Dial",
			transport: &http.Transport{
				Dial: func(network, addr string) (net.Conn, error) {
					return nil, fmt.Errorf("should never be called")
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("expected panic when transport sets %s, got none", tc.name)
				}
			}()

			cfg := GetConfigBuilder().
				SetTransport(tc.transport).
				Build()

			_ = Client(cfg)
		})
	}
}

func TestInvalidAddressFormatReturnsError(t *testing.T) {
	wc := &WrappedClient{config: GetConfigBuilder().Build()}
	run := buildRunFunc(wc)

	cases := []struct {
		name    string
		address string
	}{
		{name: "missing port", address: "127.0.0.1"},
		{name: "missing closing bracket", address: "[::1"},
		{name: "hostname without port", address: "host"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := run("tcp4", tc.address, nil)
			if err == nil {
				t.Fatal("expected error for invalid address format")
			}

			var addrErr *net.AddrError
			if !errors.As(err, &addrErr) {
				t.Fatalf("expected net.AddrError, got %T: %v", err, err)
			}
		})
	}
}

func TestIPv4MappedIPv6WithZoneReturnsInvalidHostError(t *testing.T) {
	cfg := GetConfigBuilder().Build()
	client := Client(cfg)

	_, err := client.Get("http://[::ffff:127.0.0.1%25any]")
	if err == nil {
		t.Fatal("expected error for IPv4-mapped IPv6 with zone identifier")
	}
	err = unwrap(err)
	if _, ok := err.(*InvalidHostError); !ok {
		t.Fatalf("expected InvalidHostError, got %T: %v", err, err)
	}
}
