package safeurl

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type configBuilder struct {
	timeout       time.Duration
	checkRedirect func(req *http.Request, via []*http.Request) error
	jar           http.CookieJar

	allowedPorts   []int
	allowedSchemes []string
	allowedHosts   []string
	blockedIPs     []string
	allowedIPs     []string

	blockedIPsCIDR          []string
	allowedIPsCIDR          []string
	allowSendingCredentials bool

	isIPv6Enabled         bool
	isDebugLoggingEnabled bool

	inTestMode bool
}

type Config struct {
	Timeout       time.Duration
	CheckRedirect func(req *http.Request, via []*http.Request) error
	Jar           http.CookieJar

	AllowedPorts []int

	AllowedSchemes []string

	AllowedHosts []string

	BlockedIPs []net.IP
	AllowedIPs []net.IP

	BlockedIPsCIDR []net.IPNet
	AllowedIPsCIDR []net.IPNet

	AllowSendingCredentials bool

	IsIPv6Enabled bool

	IsDebugLoggingEnabled bool
	InTestMode            bool
}

func GetConfigBuilder() *configBuilder {
	return &configBuilder{
		allowedSchemes: nil,
		allowedHosts:   nil,
		allowedPorts:   nil,
		blockedIPs:     nil,
		allowedIPs:     nil,
		blockedIPsCIDR: nil,
		allowedIPsCIDR: nil,

		isIPv6Enabled: false,

		isDebugLoggingEnabled: false,
		inTestMode:            false,
	}
}

func (cb *configBuilder) SetTimeout(timeout time.Duration) *configBuilder {
	cb.timeout = timeout
	return cb
}

func (cb *configBuilder) SetCheckRedirect(checkRedirectFunc func(req *http.Request, via []*http.Request) error) *configBuilder {
	cb.checkRedirect = checkRedirectFunc
	return cb
}

func (cb *configBuilder) SetCookieJar(jar http.CookieJar) *configBuilder {
	cb.jar = jar
	return cb
}

func (cb *configBuilder) SetAllowedSchemes(schemas ...string) *configBuilder {
	cb.allowedSchemes = schemas
	return cb
}

func (cb *configBuilder) SetAllowedHosts(hosts ...string) *configBuilder {
	cb.allowedHosts = hosts
	return cb
}

func (cb *configBuilder) SetAllowedPorts(ports ...int) *configBuilder {
	cb.allowedPorts = ports
	return cb
}

func (cb *configBuilder) SetBlockedIPs(ips ...string) *configBuilder {
	cb.blockedIPs = ips
	return cb
}

func (cb *configBuilder) SetAllowedIPs(ips ...string) *configBuilder {
	cb.allowedIPs = ips
	return cb
}

func (cb *configBuilder) SetBlockedIPsCIDR(ipsCIDR ...string) *configBuilder {
	cb.blockedIPsCIDR = ipsCIDR
	return cb
}

func (cb *configBuilder) SetAllowedIPsCIDR(ipsCIDR ...string) *configBuilder {
	cb.allowedIPsCIDR = ipsCIDR
	return cb
}

func (cb *configBuilder) EnableIPv6(enable bool) *configBuilder {
	cb.isIPv6Enabled = enable
	return cb
}

func (cb *configBuilder) EnableDebugLogging(enable bool) *configBuilder {
	cb.isDebugLoggingEnabled = enable
	return cb
}

func (cb *configBuilder) AllowSendingCredentials(allow bool) *configBuilder {
	cb.allowSendingCredentials = allow
	return cb
}

func (cb *configBuilder) EnableTestMode(enable bool) *configBuilder {
	cb.inTestMode = enable
	return cb
}

func (cb *configBuilder) Build() *Config {
	wc := &Config{
		Timeout:       cb.timeout,
		CheckRedirect: cb.checkRedirect,
		Jar:           cb.jar,

		IsIPv6Enabled:           cb.isIPv6Enabled,
		AllowSendingCredentials: cb.allowSendingCredentials,

		IsDebugLoggingEnabled: cb.isDebugLoggingEnabled,
		InTestMode:            cb.inTestMode,
	}

	if cb.allowedSchemes == nil {
		// allow only HTTP and HTTPS by default
		wc.AllowedSchemes = []string{"http", "https"}
	} else {
		for _, scheme := range cb.allowedSchemes {
			wc.AllowedSchemes = append(wc.AllowedSchemes, strings.ToLower(strings.TrimSpace(scheme)))
		}
	}

	if cb.allowedHosts == nil {
		wc.AllowedHosts = nil
	} else {
		for _, host := range cb.allowedHosts {
			wc.AllowedHosts = append(wc.AllowedHosts, strings.ToLower(strings.TrimSpace(host)))
		}
	}

	if cb.allowedPorts == nil {
		// allow only HTTP and HTTPS ports by default
		wc.AllowedPorts = append(cb.allowedPorts, 80, 443)
	} else {
		for _, port := range cb.allowedPorts {
			if port <= 0 || port > 65535 {
				panic(fmt.Sprintf("invalid port: %v", port))
			}
			wc.AllowedPorts = append(wc.AllowedPorts, port)
		}
	}

	if cb.blockedIPs == nil {
		wc.BlockedIPs = nil
	} else {
		for _, ip := range cb.blockedIPs {
			parsed := parseIP(ip)
			wc.BlockedIPs = append(wc.BlockedIPs, parsed)
		}
	}

	if cb.allowedIPs == nil {
		wc.AllowedIPs = nil
	} else {
		for _, ip := range cb.allowedIPs {
			parsed := parseIP(ip)
			wc.AllowedIPs = append(wc.AllowedIPs, parsed)
		}
	}

	if cb.blockedIPsCIDR == nil {
		wc.BlockedIPsCIDR = nil
	} else {
		for _, blockedNet := range cb.blockedIPsCIDR {
			parsedBlockedNet := parseCIDR(blockedNet)
			wc.BlockedIPsCIDR = append(wc.BlockedIPsCIDR, parsedBlockedNet)
		}
	}

	if cb.allowedIPsCIDR == nil {
		wc.AllowedIPsCIDR = nil
	} else {
		for _, allowedNet := range cb.allowedIPsCIDR {
			parsedAllowedNet := parseCIDR(allowedNet)
			wc.AllowedIPsCIDR = append(wc.AllowedIPsCIDR, parsedAllowedNet)
		}
	}

	return wc
}
