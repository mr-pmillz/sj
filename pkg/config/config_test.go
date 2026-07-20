package config

import (
	"strings"
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
	if cfg.MaxStoredResponseBytes != 64*1024 || cfg.StoreResponses {
		t.Fatalf("response storage defaults = enabled:%t bytes:%d", cfg.StoreResponses, cfg.MaxStoredResponseBytes)
	}
	if cfg.MaxCandidates != 10_000 || cfg.MaxAutomateTargets != 10_000 || cfg.BruteWorkers != 1 {
		t.Fatalf("resource defaults = brute:%d automate:%d workers:%d", cfg.MaxCandidates, cfg.MaxAutomateTargets, cfg.BruteWorkers)
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
		"stored response":    func(cfg *Config) { cfg.MaxStoredResponseBytes = 0 },
		"candidates":         func(cfg *Config) { cfg.MaxCandidates = 0 },
		"automate targets":   func(cfg *Config) { cfg.MaxAutomateTargets = 0 },
		"workers":            func(cfg *Config) { cfg.BruteWorkers = 0 },
		"preview":            func(cfg *Config) { cfg.ResponsePreview = -1 },
		"timeout overflow":   func(cfg *Config) { cfg.Timeout = maxConfiguredTimeout + time.Second },
		"response overflow":  func(cfg *Config) { cfg.MaxResponseBytes = maxConfiguredBodyBytes + 1 },
		"spec overflow":      func(cfg *Config) { cfg.MaxSpecBytes = maxConfiguredBodyBytes + 1 },
		"candidate overflow": func(cfg *Config) { cfg.MaxCandidates = maxConfiguredCandidates + 1 },
		"automate overflow":  func(cfg *Config) { cfg.MaxAutomateTargets = maxConfiguredCandidates + 1 },
		"worker overflow":    func(cfg *Config) { cfg.BruteWorkers = MaxBruteWorkers + 1 },
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

func TestValidateAutomatePresentationAndExcludedMethods(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"invalid color", func(cfg *Config) { cfg.ColorMode = "sometimes" }},
		{"empty method", func(cfg *Config) { cfg.ExcludeMethods = []string{" "} }},
		{"invalid method token", func(cfg *Config) { cfg.ExcludeMethods = []string{"GET\r\nX-Evil"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := New()
			test.mutate(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid automate option was accepted")
			}
		})
	}
}

func TestValidateSOCKS5Configuration(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"credentials without proxy", func(cfg *Config) { cfg.SOCKS5Username = "user" }},
		{"password without username", func(cfg *Config) { cfg.SOCKS5Proxy = "socks5://proxy.example"; cfg.SOCKS5Password = "secret" }},
		{"HTTP and SOCKS conflict", func(cfg *Config) {
			cfg.Proxy = "http://proxy.example:8080"
			cfg.SOCKS5Proxy = "socks5://proxy.example:1080"
		}},
		{"username too long", func(cfg *Config) {
			cfg.SOCKS5Proxy = "socks5://proxy.example"
			cfg.SOCKS5Username = strings.Repeat("u", 256)
		}},
		{"password too long", func(cfg *Config) {
			cfg.SOCKS5Proxy = "socks5://proxy.example"
			cfg.SOCKS5Username = "user"
			cfg.SOCKS5Password = strings.Repeat("p", 256)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := New()
			test.mutate(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate accepted invalid SOCKS5 configuration")
			}
		})
	}

	for _, mutate := range []func(*Config){
		func(cfg *Config) { cfg.SOCKS5Proxy = "socks5://proxy.example" },
		func(cfg *Config) {
			cfg.SOCKS5Proxy = "socks5://proxy.example"
			cfg.SOCKS5Username = "user"
			cfg.SOCKS5Password = "secret"
		},
	} {
		cfg := New()
		mutate(cfg)
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate rejected valid SOCKS5 configuration: %v", err)
		}
	}
}
