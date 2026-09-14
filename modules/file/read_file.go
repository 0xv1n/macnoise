package file

import (
	"errors"
	"io"
	"os"
)

var errNotRegularFile = errors.New("not a regular file")

func readRegularFile(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, errNotRegularFile
	}
	return io.Copy(io.Discard, f)
}
