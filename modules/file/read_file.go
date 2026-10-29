package file

import "io"

func readRegularFile(path string) (int64, error) {
	f, err := openRegularFile(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	return io.Copy(io.Discard, f)
}
