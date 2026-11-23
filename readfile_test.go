//go:build !windows

package vulnx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestReadCapped(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.json")
	if err := os.WriteFile(file, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readCapped(file, 5); err != nil || string(raw) != "12345" {
		t.Fatalf("%q %v", raw, err)
	}
	if _, err := readCapped(file, 4); err == nil {
		t.Error("a file over its cap was read")
	}
	if _, err := readCapped(dir, 1<<20); !errors.Is(err, errNotRegular) {
		t.Errorf("a directory: %v", err)
	}
	zero := filepath.Join(dir, "zero")
	if err := os.Symlink("/dev/zero", zero); err != nil {
		t.Fatal(err)
	}
	if _, err := readCapped(zero, 1<<20); !errors.Is(err, errNotRegular) {
		t.Errorf("a symlink to /dev/zero: %v", err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCapped(fifo, 1<<20); !errors.Is(err, errNotRegular) { // returns at once: nothing writes to it
		t.Errorf("a FIFO: %v", err)
	}
}

// TestHostUntrustedFiles reads no package database or os-release that is not a regular file: a symlink to
// /dev/zero or a FIFO would never end or block.
func TestHostUntrustedFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "etc/os-release", "ID=debian\nVERSION_ID=12\n")
	if err := os.MkdirAll(filepath.Join(root, "var/lib/dpkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/zero", filepath.Join(root, "var/lib/dpkg/status")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "lib/apk/db"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "lib/apk/db/installed"), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := HostEntries(context.Background(), root)
	if err != nil || len(inv.Entries) != 0 || inv.Source != "" {
		t.Errorf("%v: %q from %q", err, inv.Entries, inv.Source)
	}
}
