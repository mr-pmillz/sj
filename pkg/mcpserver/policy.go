package mcpserver

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type hostRule struct {
	all      bool
	suffix   string
	host     string
	hostPort string
}

type policy struct {
	allowActive      bool
	allowDestructive bool
	allowLocalFiles  bool
	hosts            []hostRule
	maxResults       int
	maxOutputBytes   int64
}

func newPolicy(options Options) (policy, error) {
	result := policy{
		allowActive:      options.AllowActive,
		allowDestructive: options.AllowDestructive,
		allowLocalFiles:  options.AllowLocalFiles,
		maxResults:       options.MaxResults,
		maxOutputBytes:   options.MaxOutputBytes,
	}
	for _, raw := range options.AllowedHosts {
		rule, err := parseHostRule(raw)
		if err != nil {
			return policy{}, err
		}
		result.hosts = append(result.hosts, rule)
	}
	return result, nil
}

func parseHostRule(raw string) (hostRule, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "*" {
		return hostRule{all: true}, nil
	}
	if raw == "" || strings.Contains(raw, "://") || strings.ContainsAny(raw, "/?#@") {
		return hostRule{}, fmt.Errorf("invalid allowed host %q; use a hostname, hostname:port, wildcard subdomain, IP address, or *", raw)
	}
	if strings.HasPrefix(raw, "*.") {
		suffix := strings.TrimPrefix(raw, "*")
		if !validHostname(strings.TrimPrefix(suffix, ".")) {
			return hostRule{}, fmt.Errorf("invalid allowed host wildcard %q", raw)
		}
		return hostRule{suffix: suffix}, nil
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		if !validHost(strings.Trim(host, "[]")) {
			return hostRule{}, fmt.Errorf("invalid allowed host %q", raw)
		}
		portNumber, portErr := strconv.Atoi(port)
		if portErr != nil || portNumber < 1 || portNumber > 65535 {
			return hostRule{}, fmt.Errorf("invalid allowed host port in %q", raw)
		}
		return hostRule{hostPort: raw}, nil
	}
	host := strings.Trim(raw, "[]")
	if !validHost(host) {
		return hostRule{}, fmt.Errorf("invalid allowed host %q", raw)
	}
	return hostRule{host: host}, nil
}

func validHost(host string) bool {
	return net.ParseIP(host) != nil || validHostname(host)
}

func validHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func (policy policy) checkURL(kind, raw string) error {
	parsed, err := url.Parse(raw)
	scheme := ""
	if parsed != nil {
		scheme = strings.ToLower(parsed.Scheme)
	}
	if err != nil || parsed == nil || (scheme != "http" && scheme != "https") || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("%s must be an absolute HTTP(S) URL with no user information", kind)
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	hostPort := strings.ToLower(parsed.Host)
	for _, rule := range policy.hosts {
		if rule.all || rule.host == host || rule.hostPort == hostPort || (rule.suffix != "" && strings.HasSuffix(host, rule.suffix) && host != strings.TrimPrefix(rule.suffix, ".")) {
			return nil
		}
	}
	return fmt.Errorf("%s host %q is not allowed by the MCP server", kind, host)
}

func marshalOutput(output any) ([]byte, error) {
	return json.Marshal(output)
}
