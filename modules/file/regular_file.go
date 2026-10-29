package file

import (
	"errors"
	"os"
)

var errNotRegularFile = errors.New("not a regular file")

func openRegularFile(path string) (*os.File, error) {
	f, err := openReadOnlyFile(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, errNotRegularFile
	}
	return f, nil
}
