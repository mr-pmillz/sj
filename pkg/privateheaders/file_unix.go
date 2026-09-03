//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package privateheaders

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func openValidatedFile(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("file is unavailable or is a symlink")
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("file could not be opened")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, errors.New("file metadata is unavailable")
	}
	if err := validateFileMetadata(info, os.Geteuid()); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validateFileMetadata(info os.FileInfo, effectiveUID int) error {
	if info == nil || !info.Mode().IsRegular() {
		return errors.New("file must be regular")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("file must not grant group or other permissions")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(effectiveUID) {
		return errors.New("file must be owned by the effective user")
	}
	return nil
}
