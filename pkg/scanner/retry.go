package scanner

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/output"
)

func RetryWithHints(client *httpclient.Client, cfg *config.Config, method, targetURL, postBodyData, prevResp string, prevSC int) (string, int) {
	const maxRetries = 3
	resp := prevResp
	sc := prevSC

	for attempt := 0; attempt < maxRetries && sc == 401; attempt++ {
		hints := extractMissingParams(resp)
		if len(hints) == 0 {
			break
		}

		output.PrintInfo("[retry %d] 401 response mentions missing params %v — retrying with placeholders\n", attempt+1, hints)

		if strings.ToUpper(method) == "GET" {
			sep := "&"
			if !strings.Contains(targetURL, "?") {
				sep = "?"
			}
			for _, param := range hints {
				targetURL += sep + param + "=" + cfg.TestString
				sep = "&"
			}
		} else {
			var bodyObj map[string]any
			if err := json.Unmarshal([]byte(postBodyData), &bodyObj); err == nil {
				for _, param := range hints {
					if _, exists := bodyObj[param]; !exists {
						bodyObj[param] = cfg.TestString
					}
				}
				updated, err := json.Marshal(bodyObj)
				if err == nil {
					postBodyData = string(updated)
				}
			} else {
				for _, param := range hints {
					if postBodyData != "" {
						postBodyData += "&"
					}
					postBodyData += param + "=" + cfg.TestString
				}
			}
		}

		_, newResp, newSC := client.MakeRequest(method, targetURL, io.NopCloser(bytes.NewReader([]byte(postBodyData))))
		if newResp == resp {
			break
		}
		resp = newResp
		sc = newSC
	}

	return resp, sc
}

func extractMissingParams(body string) []string {
	var params []string
	seen := map[string]bool{}

	var errObj map[string]any
	if err := json.Unmarshal([]byte(body), &errObj); err != nil {
		return nil
	}

	msg := ""
	for _, key := range []string{"message", "error", "detail", "details", "msg"} {
		if v, ok := errObj[key]; ok {
			switch val := v.(type) {
			case string:
				msg = val
			case []any:
				for _, item := range val {
					if s, ok := item.(string); ok {
						msg += " " + s
					} else if m, ok := item.(map[string]any); ok {
						if s, ok := m["message"].(string); ok {
							msg += " " + s
						}
						if s, ok := m["msg"].(string); ok {
							msg += " " + s
						}
					}
				}
			}
		}
	}

	if msg == "" {
		return nil
	}

	msgLower := strings.ToLower(msg)

	patterns := []struct {
		prefix string
		sep    string
	}{
		{"missing parameter", ","},
		{"missing required parameter", ","},
		{"required parameter", ","},
		{"missing field", ","},
		{"required field", ","},
		{"missing:", ","},
		{"required:", ","},
		{"missing subscript", ""},
	}

	for _, p := range patterns {
		idx := strings.Index(msgLower, p.prefix)
		if idx < 0 {
			continue
		}
		after := strings.TrimSpace(msg[idx+len(p.prefix):])
		after = strings.Trim(after, ".:;'\"` ")
		if after == "" {
			continue
		}

		if p.sep != "" {
			for part := range strings.SplitSeq(after, p.sep) {
				name := strings.TrimSpace(part)
				name = strings.Trim(name, "'\"` ")
				if name != "" && !seen[name] {
					seen[name] = true
					params = append(params, name)
				}
			}
		} else {
			name := strings.Fields(after)
			if len(name) > 0 {
				clean := strings.Trim(name[0], "'\"` ")
				if clean != "" && !seen[clean] {
					seen[clean] = true
					params = append(params, clean)
				}
			}
		}
	}

	return params
}
