//go:build unix && !linux

package report

import (
	"os"
	"syscall"
)

func secureOpenRootFile(root *os.Root, relative string) (*os.File, error) {
	return root.OpenFile(relative, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
