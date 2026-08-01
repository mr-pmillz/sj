package cli

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMCPCommandExposesServerPolicyFlags(t *testing.T) {
	if command, _, err := rootCmd.Find([]string{"mcp"}); err != nil || command != mcpCmd {
		t.Fatalf("root command does not expose mcp: command=%v err=%v", command, err)
	}
	for _, name := range []string{
		"allow-host",
		"allow-local-files",
		"allow-active",
		"allow-destructive",
		"assessment-root",
		"assessment-evidence-key-file",
		"max-results",
		"max-output-bytes",
		"max-input-bytes",
		"max-concurrent",
	} {
		if mcpCmd.Flags().Lookup(name) == nil {
			t.Errorf("mcp command is missing --%s", name)
		}
	}
}

func TestLoadMCPAssessmentEvidenceKeyUsesBoundedSecureFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "assessment.key")
	want := bytes.Repeat([]byte{0x42}, 32)
	if err := os.WriteFile(path, []byte("base64:"+base64.StdEncoding.EncodeToString(want)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadMCPAssessmentEvidenceKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("decoded key = %x, want %x", got, want)
	}

	if runtime.GOOS != "windows" {
		permissive := filepath.Join(directory, "permissive.key")
		if err := os.WriteFile(permissive, []byte(strings.Repeat("a", 64)), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadMCPAssessmentEvidenceKey(permissive); err == nil || !strings.Contains(err.Error(), "0600") {
			t.Fatalf("permissive key error = %v", err)
		}
	}

	link := filepath.Join(directory, "linked.key")
	if err := os.Symlink(path, link); err == nil {
		if _, err := loadMCPAssessmentEvidenceKey(link); err == nil || !strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("symlink key error = %v", err)
		}
	}

	oversized := filepath.Join(directory, "oversized.key")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte{'a'}, int(maxMCPAssessmentEvidenceKeyFileBytes)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMCPAssessmentEvidenceKey(oversized); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized key error = %v", err)
	}
}

func TestLoadMCPAssessmentEvidenceKeyFallsBackToExistingEnvironmentDecoder(t *testing.T) {
	t.Setenv(assessmentEvidenceKeyEnvironment, "hex:"+strings.Repeat("5a", 32))
	key, err := loadMCPAssessmentEvidenceKey("")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, bytes.Repeat([]byte{0x5a}, 32)) {
		t.Fatalf("environment key = %x", key)
	}
}
