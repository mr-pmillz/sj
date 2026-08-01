package mcpserver

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
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
	assessmentRoots  []string
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
	for _, raw := range options.AssessmentRoots {
		root, err := canonicalAssessmentRoot(raw)
		if err != nil {
			return policy{}, err
		}
		if !slicesContain(result.assessmentRoots, root) {
			result.assessmentRoots = append(result.assessmentRoots, root)
		}
	}
	return result, nil
}

func canonicalAssessmentRoot(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("assessment root must not be empty")
	}
	absolute, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("resolve assessment root: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve assessment root: %w", err)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", fmt.Errorf("inspect assessment root: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("assessment root %q is not a directory", raw)
	}
	return filepath.Clean(canonical), nil
}

func slicesContain(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
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

func (policy policy) checkAssessmentPath(kind, raw string) (string, error) {
	if len(policy.assessmentRoots) == 0 {
		return "", fmt.Errorf("assessment local access requires at least one operator-configured assessment root")
	}
	if !filepath.IsAbs(raw) {
		return "", fmt.Errorf("%s must be an absolute path", kind)
	}
	canonical, err := filepath.EvalSymlinks(filepath.Clean(raw))
	if err != nil {
		return "", fmt.Errorf("%s is unavailable: %w", kind, err)
	}
	if policy.assessmentPathWithinRoot(canonical) {
		return canonical, nil
	}
	return "", fmt.Errorf("%s is outside the operator-configured assessment roots", kind)
}

func (policy policy) checkAssessmentDatabasePath(raw string) (string, error) {
	if len(policy.assessmentRoots) == 0 {
		return "", fmt.Errorf("assessment database requires at least one operator-configured assessment root")
	}
	absolute, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("resolve assessment database path: %w", err)
	}
	cleaned := filepath.Clean(absolute)
	info, err := os.Lstat(cleaned)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", fmt.Errorf("assessment database must be a regular non-symlink file")
		}
		canonical, evalErr := filepath.EvalSymlinks(cleaned)
		if evalErr != nil {
			return "", fmt.Errorf("resolve assessment database: %w", evalErr)
		}
		if !policy.assessmentPathWithinRoot(canonical) {
			return "", fmt.Errorf("assessment database is outside the operator-configured assessment roots")
		}
		return canonical, nil
	case !os.IsNotExist(err):
		return "", fmt.Errorf("inspect assessment database: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(cleaned))
	if err != nil {
		return "", fmt.Errorf("resolve assessment database parent: %w", err)
	}
	if !policy.assessmentPathWithinRoot(parent) {
		return "", fmt.Errorf("assessment database parent is outside the operator-configured assessment roots")
	}
	return filepath.Join(parent, filepath.Base(cleaned)), nil
}

func (policy policy) checkAssessmentOutputDirectoryPath(raw string) (string, error) {
	if len(policy.assessmentRoots) == 0 {
		return "", fmt.Errorf("full-workflow output requires at least one operator-configured assessment root")
	}
	if !filepath.IsAbs(raw) {
		return "", fmt.Errorf("full-workflow output_directory must be an absolute path")
	}
	cleaned := filepath.Clean(raw)
	if _, err := os.Lstat(cleaned); err == nil {
		return "", fmt.Errorf("full-workflow output_directory already exists")
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("inspect full-workflow output_directory: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(cleaned))
	if err != nil {
		return "", fmt.Errorf("resolve full-workflow output parent: %w", err)
	}
	if !policy.assessmentPathWithinRoot(parent) {
		return "", fmt.Errorf("full-workflow output_directory is outside the operator-configured assessment roots")
	}
	return filepath.Join(parent, filepath.Base(cleaned)), nil
}

func (policy policy) assessmentPathWithinRoot(canonical string) bool {
	_, found := policy.assessmentRootForPath(canonical)
	return found
}

func (policy policy) assessmentRootForPath(canonical string) (string, bool) {
	for _, root := range policy.assessmentRoots {
		relative, err := filepath.Rel(root, canonical)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return root, true
		}
	}
	return "", false
}

func marshalOutput(output any) ([]byte, error) {
	return json.Marshal(output)
}
