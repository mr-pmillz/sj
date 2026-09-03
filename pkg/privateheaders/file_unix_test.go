//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package privateheaders

import (
	"os"
	"testing"
)

func TestFileMetadataRejectsWrongOwner(t *testing.T) {
	path := writeHeaderFile(t, "X-Test: value\n", 0o600)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFileMetadata(info, os.Geteuid()+1); err == nil {
		t.Fatal("metadata validation accepted a different effective UID")
	}
}
