package openapi

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/output"
)

func PrintSpecInfo(spec map[string]interface{}, w *output.Writer, cfg *config.Config) {
	info, ok := spec["info"].(map[string]interface{})
	if !ok || info == nil {
		output.PrintInfo("No information defined in the documentation.\n")
		return
	}

	title, _ := info["title"].(string)
	if title != "" {
		w.SpecTitle = title
		ofmt := strings.ToLower(cfg.OutputFormat)
		if ofmt != "json" && ofmt != "jsonl" && ofmt != "csv" {
			fmt.Printf("Title: %s\n", title)
		} else {
			output.PrintInfo("Title: %s\n", title)
		}
	}

	description, _ := info["description"].(string)
	if description != "" {
		w.SpecDescription = description
		ofmt := strings.ToLower(cfg.OutputFormat)
		if ofmt != "json" && ofmt != "jsonl" && ofmt != "csv" {
			fmt.Printf("Description: %s\n", description)
		} else {
			output.PrintInfo("Description: %s\n", description)
		}
	}
}

func NormalizeBasePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path == "/" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.TrimRight(path, "/")
	if path == "/" {
		return ""
	}
	return path
}

func SetScheme(swaggerURL string) string {
	if strings.HasPrefix(swaggerURL, "http://") {
		return "http"
	}
	return "https"
}

func TrimHostScheme(apiTarget, fullURLHost string) string {
	if apiTarget != "" {
		return strings.TrimPrefix(strings.TrimPrefix(apiTarget, "http://"), "https://")
	}
	return fullURLHost
}

func LooksLikeJSSpec(b []byte, swaggerURL, localFile, format string) bool {
	if strings.HasSuffix(strings.ToLower(swaggerURL), ".js") ||
		strings.HasSuffix(strings.ToLower(localFile), ".js") ||
		strings.ToLower(format) == "js" {
		return true
	}
	trimmed := bytes.TrimLeft(b, " \t\r\n")
	prefixes := [][]byte{
		[]byte("var "), []byte("let "), []byte("const "),
		[]byte("(function"), []byte("window."),
		[]byte("//"), []byte("/*"),
	}
	for _, p := range prefixes {
		if bytes.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}
