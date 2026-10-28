// Package ownership tracks files and directories created by one invocation.
package ownership

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// File identifies one file version tracked by MacNoise.
type File struct {
	path string
	info os.FileInfo
	hash [sha256.Size]byte
}

// CreateFile creates a new file without replacing an existing path.
func CreateFile(path string, data []byte, mode os.FileMode) (File, error) {
	return CreateFileFrom(path, bytes.NewReader(data), mode)
}

// CreateFileFrom streams src into a new file without replacing an existing path.
func CreateFileFrom(path string, src io.Reader, mode os.FileMode) (File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return File{}, err
	}
	createdInfo, statErr := f.Stat()
	if statErr != nil {
		_ = f.Close()
		return File{}, statErr
	}
	h := sha256.New()
	_, writeErr := io.Copy(io.MultiWriter(f, h), src)
	info, finalStatErr := f.Stat()
	closeErr := f.Close()
	if err := errors.Join(writeErr, finalStatErr, closeErr); err != nil {
		removeFileIfSame(path, createdInfo)
		return File{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return File{path: path, info: info, hash: digest}, nil
}

// CaptureFile records the identity and contents of an existing regular file.
func CaptureFile(path string) (File, error) {
	return captureFile(path)
}

func captureFile(path string) (File, error) {
	entryInfo, err := os.Lstat(path)
	if err != nil {
		return File{}, err
	}
	if !entryInfo.Mode().IsRegular() {
		return File{}, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return File{}, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return File{}, err
	}
	if !os.SameFile(entryInfo, info) {
		return File{}, fmt.Errorf("%s changed while it was inspected", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return File{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return File{path: path, info: entryInfo, hash: digest}, nil
}

func removeFileIfSame(path string, owned os.FileInfo) {
	current, err := os.Lstat(path)
	if err == nil && current.Mode().IsRegular() && os.SameFile(owned, current) {
		_ = os.Remove(path)
	}
}

// Path returns the tracked file path.
func (f File) Path() string {
	return f.path
}

// AtPath tracks the same captured file identity and contents at another path.
func (f File) AtPath(path string) File {
	f.path = path
	return f
}

// Size returns the captured file size.
func (f File) Size() int64 {
	if f.info == nil {
		return 0
	}
	return f.info.Size()
}

// Verify checks that the file identity and contents still match.
func (f File) Verify() error {
	return f.verify(false)
}

func (f File) verify(allowMissing bool) error {
	if f.path == "" {
		return nil
	}
	current, err := captureFile(f.path)
	if os.IsNotExist(err) {
		if allowMissing {
			return nil
		}
		return fmt.Errorf("cleanup conflict: %s was removed", f.path)
	}
	if err != nil {
		return fmt.Errorf("cleanup conflict: cannot safely inspect %s: %w", f.path, err)
	}
	if !os.SameFile(f.info, current.info) || f.hash != current.hash {
		return fmt.Errorf("cleanup conflict: %s changed after macnoise wrote it", f.path)
	}
	return nil
}

// Remove deletes the file only when its identity and contents still match.
func (f File) Remove() error {
	if f.path == "" {
		return nil
	}
	if err := f.verify(true); err != nil {
		return err
	}
	if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// RemoveFiles removes tracked files in reverse creation order.
func RemoveFiles(files []File) error {
	var errs []error
	for index := len(files) - 1; index >= 0; index-- {
		if err := files[index].Remove(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Directory identifies one directory created by MacNoise.
type Directory struct {
	path string
	info os.FileInfo
}

// EnsureDirectories creates missing directories beneath the nearest existing
// parent and returns only the directories it created.
func EnsureDirectories(path string, mode os.FileMode) ([]Directory, error) {
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

	created := make([]Directory, 0, len(missing))
	for index := len(missing) - 1; index >= 0; index-- {
		current := missing[index]
		if err := os.Mkdir(current, mode); err != nil {
			return created, err
		}
		info, err := os.Stat(current)
		if err != nil {
			return created, err
		}
		created = append(created, Directory{path: current, info: info})
	}
	return created, nil
}

// RemoveDirectories removes unchanged owned directories in child-first order.
func RemoveDirectories(dirs []Directory) error {
	var errs []error
	for index := len(dirs) - 1; index >= 0; index-- {
		dir := dirs[index]
		info, err := os.Lstat(dir.path)
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
