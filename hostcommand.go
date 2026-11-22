package vulnx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// cappedBuffer keeps the first limit bytes written to it and notes that more came: a program's output read into
// memory has a bound. A write past the bound reports success, so the program is not stopped mid-write by an error.
type cappedBuffer struct {
	mu        sync.Mutex
	limit     int
	buffer    bytes.Buffer
	truncated bool
}

func (b *cappedBuffer) Len() int { b.mu.Lock(); defer b.mu.Unlock(); return b.buffer.Len() }
func (b *cappedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buffer.Bytes())
}
func (b *cappedBuffer) Truncated() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.truncated }
func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if room := b.limit - b.buffer.Len(); len(p) > room {
		p = p[:room]
		b.truncated = true
	}
	if _, err := b.buffer.Write(p); err != nil {
		return 0, err
	}
	return n, nil
}

// commandWaitDelay is how long a killed program's output pipes are waited for before they are closed.
const commandWaitDelay = time.Second

// newCommand prepares a program to run in a process group of its own, so that it and anything it starts are
// killed when ctx ends. path is absolute: PATH is not trusted to name the program.
func newCommand(ctx context.Context, path string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.WaitDelay = commandWaitDelay
	killGroupOnCancel(cmd)
	return cmd
}

// runCapped runs a program and returns its standard output, failing when it writes more than limit bytes.
func runCapped(ctx context.Context, limit int, path string, args ...string) ([]byte, error) {
	return runCappedInput(ctx, nil, limit, path, args...)
}

// runCappedInput is runCapped with input as the program's standard input.
func runCappedInput(ctx context.Context, input []byte, limit int, path string, args ...string) ([]byte, error) {
	cmd := newCommand(ctx, path, args...)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	out := &cappedBuffer{limit: limit}
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return nil, errors.Join(fmt.Errorf("%s: %w", path, err), ctx.Err())
	}
	if out.Truncated() {
		return nil, fmt.Errorf("%s: output larger than %d MiB", path, limit>>20)
	}
	return out.Bytes(), nil
}
