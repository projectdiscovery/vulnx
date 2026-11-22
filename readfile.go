package vulnx

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// Size caps for the files vulnx reads from disk. A file over its cap is refused, not cut: a cut file reads wrong.
const (
	maxConfigFile = 4 << 20  // a configuration, manifest, metadata or property list
	maxPackageDB  = 64 << 20 // dpkg's status file, apk's installed database
	maxUploadFile = 96 << 20 // a file uploaded for scanning: the API takes an image tarball up to 95 MiB
)

// errNotRegular is a path that names a FIFO, a device, a socket or a directory where a file is expected.
var errNotRegular = errors.New("not a regular file")

// openRegular opens a file for reading only when it is a regular file: a FIFO or a device planted where a file is
// expected (a symlink to /dev/zero, a named pipe) would block or never end. O_NONBLOCK keeps the open itself from
// waiting for a FIFO's writer.
func openRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err == nil && !st.Mode().IsRegular() {
		err = fmt.Errorf("%s: %w", path, errNotRegular)
	}
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

// readCapped reads a regular file of at most limit bytes.
func readCapped(path string, limit int64) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s: larger than %d MiB", path, limit>>20)
	}
	return raw, nil
}

// ReadUpload reads a file given to vulnx scan: a regular file, no larger than the API takes.
func ReadUpload(path string) ([]byte, error) {
	return readCapped(path, maxUploadFile)
}
