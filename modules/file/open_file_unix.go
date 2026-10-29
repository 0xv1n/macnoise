//go:build unix

package file

import (
	"os"
	"syscall"
)

func openReadOnlyFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
