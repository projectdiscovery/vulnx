//go:build !windows

package vulnx

import (
	"os/exec"
	"syscall"
)

// killGroupOnCancel starts cmd as the leader of a new process group and makes cancelling it kill the whole group.
func killGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}
