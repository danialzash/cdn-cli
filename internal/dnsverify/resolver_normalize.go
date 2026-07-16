package dnsverify

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// NormalizeResolverAddress parses a resolver value into host:port form.
func NormalizeResolverAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("resolver address is empty")
	}

	if strings.HasPrefix(value, "[") && !strings.Contains(value, "]") {
		return "", fmt.Errorf("invalid resolver address %q", value)
	}

	if host, port, err := net.SplitHostPort(value); err == nil {
		if host == "" || port == "" {
			return "", fmt.Errorf("invalid resolver address %q", value)
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", fmt.Errorf("invalid resolver port %q", port)
		}
		return net.JoinHostPort(host, strconv.Itoa(portNumber)), nil
	}

	unbracketed := strings.Trim(value, "[]")
	if ip := net.ParseIP(unbracketed); ip != nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}

	if strings.Count(value, ":") == 0 {
		return net.JoinHostPort(value, "53"), nil
	}

	return "", fmt.Errorf("invalid resolver address %q", value)
}

// NormalizeResolvers normalizes a list of resolver addresses.
func NormalizeResolvers(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized, err := NormalizeResolverAddress(value)
		if err != nil {
			return nil, err
		}
		out = append(out, normalized)
	}
	return out, nil
}
