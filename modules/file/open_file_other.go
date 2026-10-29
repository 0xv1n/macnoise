//go:build !unix

package file

import "os"

func openReadOnlyFile(path string) (*os.File, error) {
	return os.Open(path)
}
