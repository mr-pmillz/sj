//go:build linux

package report

import (
	"os"
	"syscall"
)

// secureOpenRootFile combines os.Root's beneath-root resolution with
// non-blocking, no-follow open flags. The opened handle is subsequently
// verified with File.Stat before any reads occur.
func secureOpenRootFile(root *os.Root, relative string) (*os.File, error) {
	return root.OpenFile(relative, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
