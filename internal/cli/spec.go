package cli

import (
	"io"
	"os"
	"path/filepath"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/output"
)

func loadSpec(cfg *config.Config, client *httpclient.Client) []byte {
	if cfg.SwaggerURL != "" {
		bodyBytes, _, _ := client.MakeRequest("GET", cfg.SwaggerURL, nil)
		return bodyBytes
	}

	specFile, err := os.Open(cfg.LocalFile)
	if err != nil {
		output.Die("Error opening file: %v", err)
	}
	defer specFile.Close()

	cfg.SpecBaseDir = filepath.Dir(cfg.LocalFile)
	if cfg.SpecBaseDir == "." {
		if absPath, err := filepath.Abs(cfg.LocalFile); err == nil {
			cfg.SpecBaseDir = filepath.Dir(absPath)
		}
	}

	bodyBytes, _ := io.ReadAll(specFile)
	return bodyBytes
}
