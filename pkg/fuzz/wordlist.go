package fuzz

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mr-pmillz/sj/pkg/apitest"
)

const (
	maximumSpecialCharacterEntries = apitest.MaximumSpecialCharacterEntries
	maximumSpecialCharacterBytes   = 64 * 1024
)

// LoadSpecialCharacterWordlist loads a bounded, line-oriented corpus. Values
// are preserved as logical input values: a raw ! and a literal %21 remain two
// distinct probes, with normal URL serialization applied later by Mutations.
func LoadSpecialCharacterWordlist(path string) ([]string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("special-character wordlist path must not be empty")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect special-character wordlist: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("special-character wordlist must be a regular non-symlink file")
	}
	if info.Size() > maximumSpecialCharacterBytes {
		return nil, fmt.Errorf("special-character wordlist exceeds the %d-byte limit", maximumSpecialCharacterBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open special-character wordlist: %w", err)
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, maximumSpecialCharacterBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read special-character wordlist: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close special-character wordlist: %w", closeErr)
	}
	if len(contents) > maximumSpecialCharacterBytes {
		return nil, fmt.Errorf("special-character wordlist exceeds the %d-byte limit", maximumSpecialCharacterBytes)
	}

	lines := strings.Split(string(contents), "\n")
	values := make([]string, 0, min(len(lines), maximumSpecialCharacterEntries))
	for index, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if index == 0 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		if line != "" {
			values = append(values, line)
		}
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("special-character wordlist contains no special-character payloads")
	}
	if len(values) > maximumSpecialCharacterEntries {
		return nil, fmt.Errorf("special-character wordlist may contain at most %d payloads", maximumSpecialCharacterEntries)
	}
	if err := apitest.ValidateSpecialCharacters(values); err != nil {
		return nil, fmt.Errorf("special-character wordlist: %w", err)
	}
	return values, nil
}
