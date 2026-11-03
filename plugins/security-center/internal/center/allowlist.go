package security_center

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Allowlist entries only describe source addresses resolved by Nginx. They never
// authorize forwarded headers or change the trusted proxy configuration.
func mergeIPAllowlist(lists ...[]string) ([]string, error) {
	seen := map[string]bool{}
	for _, list := range lists {
		if len(list) > 400 {
			return nil, fmt.Errorf("%w: at most 400 IP/CIDR entries", ErrInvalid)
		}
		for _, value := range list {
			if value == "" || value != strings.TrimSpace(value) {
				return nil, fmt.Errorf("%w: invalid IP/CIDR", ErrInvalid)
			}
			var prefix netip.Prefix
			if strings.Contains(value, "/") {
				var err error
				prefix, err = netip.ParsePrefix(value)
				if err != nil {
					return nil, fmt.Errorf("%w: invalid IP/CIDR", ErrInvalid)
				}
				if prefix.Addr().Is4In6() {
					return nil, fmt.Errorf("%w: use IPv4 notation for mapped IPv4 networks", ErrInvalid)
				}
			} else {
				addr, err := netip.ParseAddr(value)
				if err != nil || addr.Zone() != "" {
					return nil, fmt.Errorf("%w: invalid IP/CIDR", ErrInvalid)
				}
				addr = addr.Unmap()
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			seen[prefix.Masked().String()] = true
		}
	}
	if len(seen) > 400 {
		return nil, fmt.Errorf("%w: combined allowlist exceeds 400 entries", ErrInvalid)
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

// Debian libModSecurity rejects explicit IPv6 /128 and /0 masks. Bare IPv6
// means one host; two /1 networks exactly represent the corresponding /0.
// API/Lua keep canonical CIDRs unchanged.
func modSecurityIPMatch(ranges []string) string {
	result := make([]string, 0, len(ranges))
	for _, value := range ranges {
		switch value {
		case "0.0.0.0/0":
			result = append(result, "0.0.0.0/1", "128.0.0.0/1")
		case "::/0":
			result = append(result, "::/1", "8000::/1")
		default:
			result = append(result, strings.TrimSuffix(value, "/128"))
		}
	}
	return strings.Join(result, ",")
}
