package safeurl

import (
	"fmt"
	"strconv"
)

func isPortAllowed(port string, allowedPorts []int) bool {
	porti, err := strconv.Atoi(port)
	if err != nil {
		panic(fmt.Sprintf("failed to parse port: %v", port))
	}
	return _isPortAllowed(porti, allowedPorts)
}

func _isPortAllowed(port int, allowedPorts []int) bool {
	for _, blockedPort := range allowedPorts {
		if port == blockedPort {
			return true
		}
	}
	return false
}
