package vulnx

import (
	"bytes"
	"context"
	"io"
	"runtime"
	"testing"
	"time"
)

func TestCappedBuffer(t *testing.T) {
	buf := cappedBuffer{limit: 8}
	if _, err := io.Copy(&buf, struct{ io.Reader }{bytes.NewReader([]byte("0123456789"))}); err != nil {
		t.Fatal(err)
	}
	if string(buf.Bytes()) != "01234567" || !buf.Truncated() {
		t.Fatalf("cap bypass: %q truncated=%v", buf.Bytes(), buf.Truncated())
	}
}

// TestRunCapped refuses more output than its cap, and on cancel kills what the program started as well.
func TestRunCapped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /bin/sh")
	}
	if out, err := runCapped(context.Background(), 16, "/bin/sh", "-c", "printf hello"); err != nil || string(out) != "hello" {
		t.Fatalf("%q %v", out, err)
	}
	if _, err := runCapped(context.Background(), 4, "/bin/sh", "-c", "printf hello"); err == nil {
		t.Error("output over the cap was returned")
	}
	if out, err := runCappedInput(context.Background(), []byte("in"), 16, "/bin/cat"); err != nil || string(out) != "in" {
		t.Errorf("stdin: %q %v", out, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	// the child keeps stdout open: unless its whole group is killed, the run lasts its sleep
	if _, err := runCapped(ctx, 16, "/bin/sh", "-c", "sleep 30 & sleep 30"); err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("err %v after %s", err, time.Since(start))
	}
}
