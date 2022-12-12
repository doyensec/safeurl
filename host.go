package safeurl

import "strings"

func isAllowedHost(host string, allowedHosts []string) bool {
	host = strings.ToLower(host)
	for _, allowedHost := range allowedHosts {
		if host == allowedHost {
			return true
		}
	}
	return false
}