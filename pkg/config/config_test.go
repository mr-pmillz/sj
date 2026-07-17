package config

import (
	"testing"
	"time"
)

func TestNewUsesBoundedProductionDefaults(t *testing.T) {
	cfg := New()
	if cfg.Timeout != 30*time.Second {
		t.Fatalf("timeout = %s", cfg.Timeout)
	}
	if cfg.MaxResponseBytes != 10*1024*1024 || cfg.MaxSpecBytes != 10*1024*1024 {
		t.Fatalf("size limits = response:%d spec:%d", cfg.MaxResponseBytes, cfg.MaxSpecBytes)
	}
	if cfg.MaxCandidates != 10_000 {
		t.Fatalf("candidate limit = %d", cfg.MaxCandidates)
	}
	if cfg.Mode != ModeUnknown {
		t.Fatalf("default mode = %v, want unknown", cfg.Mode)
	}
}

func TestValidateRejectsNonPositiveResourceLimits(t *testing.T) {
	tests := map[string]func(*Config){
		"timeout":            func(cfg *Config) { cfg.Timeout = 0 },
		"response":           func(cfg *Config) { cfg.MaxResponseBytes = 0 },
		"spec":               func(cfg *Config) { cfg.MaxSpecBytes = 0 },
		"candidates":         func(cfg *Config) { cfg.MaxCandidates = 0 },
		"preview":            func(cfg *Config) { cfg.ResponsePreview = -1 },
		"timeout overflow":   func(cfg *Config) { cfg.Timeout = maxConfiguredTimeout + time.Second },
		"response overflow":  func(cfg *Config) { cfg.MaxResponseBytes = maxConfiguredBodyBytes + 1 },
		"spec overflow":      func(cfg *Config) { cfg.MaxSpecBytes = maxConfiguredBodyBytes + 1 },
		"candidate overflow": func(cfg *Config) { cfg.MaxCandidates = maxConfiguredCandidates + 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := New()
			mutate(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate accepted invalid configuration")
			}
		})
	}
}

func TestValidateRejectsMalformedOrInjectedHeaders(t *testing.T) {
	for _, header := range []string{"missing colon", "Bad Header: value", "X-Test: safe\r\nX-Evil: yes"} {
		cfg := New()
		cfg.Headers = []string{header}
		if err := cfg.Validate(); err == nil {
			t.Errorf("accepted invalid header %q", header)
		}
	}
	cfg := New()
	cfg.Headers = []string{"Authorization: Bearer token", "X-Custom: value:with:colons"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("rejected valid headers: %v", err)
	}
}
