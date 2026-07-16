package checkup

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q", raw)
	}
	return port, nil
}

func normalizeOriginHost(host string) string {
	host = strings.TrimSpace(host)
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.String()
	}
	return host
}

func joinOriginAddress(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func parseOriginHostPort(origin string, explicitPort int) (host string, port int, portProvided bool, err error) {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return "", 0, false, fmt.Errorf("origin is empty")
	}

	if strings.HasPrefix(origin, "[") {
		if !strings.Contains(origin, "]") {
			return "", 0, false, fmt.Errorf("invalid origin address %q", origin)
		}
		bracketHost, rest, _ := strings.Cut(origin, "]")
		host = strings.TrimPrefix(bracketHost, "[")
		rest = strings.TrimPrefix(rest, ":")
		embeddedPort := 0
		if rest != "" {
			embeddedPort, err = parsePort(rest)
			if err != nil {
				return "", 0, false, fmt.Errorf("invalid origin address %q", origin)
			}
		}
		if net.ParseIP(host) == nil {
			return "", 0, false, fmt.Errorf("invalid origin address %q", origin)
		}
		host = normalizeOriginHost(host)
		if explicitPort != 0 {
			if err := validatePort(explicitPort); err != nil {
				return "", 0, false, err
			}
			return host, explicitPort, true, nil
		}
		if embeddedPort != 0 {
			return host, embeddedPort, true, nil
		}
		return host, 0, false, nil
	}

	if h, p, splitErr := net.SplitHostPort(origin); splitErr == nil {
		host = normalizeOriginHost(h)
		if explicitPort != 0 {
			if err := validatePort(explicitPort); err != nil {
				return "", 0, false, err
			}
			return host, explicitPort, true, nil
		}
		port, err = parsePort(p)
		if err != nil {
			return "", 0, false, fmt.Errorf("invalid origin address %q", origin)
		}
		return host, port, true, nil
	}

	if strings.Count(origin, ":") > 0 {
		if net.ParseIP(origin) == nil {
			return "", 0, false, fmt.Errorf("invalid origin address %q", origin)
		}
	}

	host = normalizeOriginHost(origin)
	if explicitPort != 0 {
		if err := validatePort(explicitPort); err != nil {
			return "", 0, false, err
		}
		return host, explicitPort, true, nil
	}
	return host, 0, false, nil
}
