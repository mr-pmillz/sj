//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package privateheaders

import (
	"errors"
	"os"
)

func openValidatedFile(string) (*os.File, error) {
	return nil, errors.New("effective user ownership cannot be verified on this platform")
}
