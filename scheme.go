package safeurl

import "strings"

func isSchemeAllowed(scheme string, allowedSchemes []string) bool {
	scheme = strings.ToLower(scheme)
	for _, allowedScheme := range allowedSchemes {
		if scheme == allowedScheme {
			return true
		}
	}
	return false
}
