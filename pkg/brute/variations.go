package brute

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var versionRe = regexp.MustCompile(`(.*/)v(\d+)(/.*|$)`)

func GeneratePathVariations(foundURL string) []string {
	u, err := url.Parse(foundURL)
	if err != nil {
		return nil
	}
	base := u.Scheme + "://" + u.Host
	path := u.Path
	seen := map[string]bool{foundURL: true}
	var results []string

	add := func(newURL string) {
		if !seen[newURL] {
			seen[newURL] = true
			results = append(results, newURL)
		}
	}

	if m := versionRe.FindStringSubmatch(path); m != nil {
		origVersion, _ := strconv.Atoi(m[2])
		prefix, suffix := m[1], m[3]
		for v := 1; v <= 5; v++ {
			if v != origVersion {
				add(base + fmt.Sprintf("%sv%d%s", prefix, v, suffix))
			}
		}
	}

	extSwaps := map[string][]string{
		".json": {".yaml", ".yml"},
		".yaml": {".json", ".yml"},
		".yml":  {".json", ".yaml"},
	}
	for ext, alts := range extSwaps {
		if strings.HasSuffix(path, ext) {
			stem := strings.TrimSuffix(path, ext)
			for _, alt := range alts {
				add(base + stem + alt)
			}
		}
	}

	dir := path
	if idx := strings.LastIndex(dir, "/"); idx >= 0 {
		dir = dir[:idx]
	}
	siblings := []string{
		"/swagger.json", "/openapi.json", "/swagger.yaml", "/openapi.yaml",
		"/api-docs", "/api-docs.json",
	}
	for _, sib := range siblings {
		add(base + dir + sib)
	}

	return results
}
