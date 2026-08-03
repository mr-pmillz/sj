package fuzz

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadSpecialCharacterWordlistPreservesRawAndEncodedValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "special-characters.txt")
	if err := os.WriteFile(path, []byte("!\n%21\n#\n\\\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	values, err := LoadSpecialCharacterWordlist(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"!", "%21", "#", `\`}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("special-character values = %#v, want %#v", values, want)
	}
}

func TestLoadSpecialCharacterWordlistRejectsUnsafeOrAmbiguousInput(t *testing.T) {
	testCases := []struct {
		name     string
		contents string
		want     string
	}{
		{name: "empty", contents: "\n", want: "no special-character payloads"},
		{name: "multiple characters", contents: "ab\n", want: "exactly one special character"},
		{name: "encoded control", contents: "%0A\n", want: "control or whitespace"},
		{name: "encoded letter", contents: "%41\n", want: "letter or digit"},
		{name: "duplicate", contents: "!\n!\n", want: "duplicate"},
		{name: "too many", contents: strings.Repeat("!\n", maximumSpecialCharacterEntries+1), want: "at most"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "special-characters.txt")
			if err := os.WriteFile(path, []byte(testCase.contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadSpecialCharacterWordlist(path); err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want substring %q", err, testCase.want)
			}
		})
	}
}

func TestLoadSpecialCharacterWordlistRejectsSymlinks(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "special-characters.txt")
	if err := os.WriteFile(target, []byte("!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "special-characters-link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSpecialCharacterWordlist(link); err == nil || !strings.Contains(err.Error(), "regular non-symlink") {
		t.Fatalf("symlink error = %v", err)
	}
}
