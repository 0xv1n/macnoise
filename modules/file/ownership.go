package file

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type ownedFile struct {
	path string
	info os.FileInfo
	hash [sha256.Size]byte
}

type ownedDir struct {
	path string
	info os.FileInfo
}

func createOwnedFile(path string, data []byte, mode os.FileMode) (ownedFile, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return ownedFile{}, err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(path)
		return ownedFile{}, err
	}
	owned, err := captureOwnedFile(path)
	if err != nil {
		_ = os.Remove(path)
		return ownedFile{}, err
	}
	return owned, nil
}

func captureOwnedFile(path string) (ownedFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return ownedFile{}, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return ownedFile{}, err
	}
	if !info.Mode().IsRegular() {
		return ownedFile{}, fmt.Errorf("%s is not a regular file", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ownedFile{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return ownedFile{path: path, info: info, hash: digest}, nil
}

func (f ownedFile) verifyCurrent() error {
	if f.path == "" {
		return nil
	}
	current, err := captureOwnedFile(f.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s during cleanup: %w", f.path, err)
	}
	if !os.SameFile(f.info, current.info) || f.hash != current.hash {
		return fmt.Errorf("cleanup conflict: %s changed after macnoise wrote it", f.path)
	}
	return nil
}

func removeOwnedFile(f ownedFile) error {
	if f.path == "" {
		return nil
	}
	if err := f.verifyCurrent(); err != nil {
		return err
	}
	if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func removeOwnedFiles(files []ownedFile) error {
	var errs []error
	for index := len(files) - 1; index >= 0; index-- {
		if err := removeOwnedFile(files[index]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func ensureDirs(path string, mode os.FileMode) ([]ownedDir, error) {
	path = filepath.Clean(path)
	var missing []string
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err == nil {
			if !info.IsDir() {
				return nil, fmt.Errorf("%s is not a directory", current)
			}
			break
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return nil, fmt.Errorf("cannot find an existing parent for %s", path)
		}
	}

	created := make([]ownedDir, 0, len(missing))
	for index := len(missing) - 1; index >= 0; index-- {
		current := missing[index]
		if err := os.Mkdir(current, mode); err != nil {
			return created, err
		}
		info, err := os.Stat(current)
		if err != nil {
			return created, err
		}
		created = append(created, ownedDir{path: current, info: info})
	}
	return created, nil
}

func removeOwnedDirs(dirs []ownedDir) error {
	var errs []error
	for index := len(dirs) - 1; index >= 0; index-- {
		dir := dirs[index]
		info, err := os.Stat(dir.path)
		switch {
		case os.IsNotExist(err):
			continue
		case err != nil:
			errs = append(errs, err)
			continue
		case !info.IsDir() || !os.SameFile(dir.info, info):
			errs = append(errs, fmt.Errorf("cleanup conflict: %s was replaced", dir.path))
			continue
		}
		if err := os.Remove(dir.path); err != nil {
			errs = append(errs, fmt.Errorf("cleanup directory %s: %w", dir.path, err))
		}
	}
	return errors.Join(errs...)
}
