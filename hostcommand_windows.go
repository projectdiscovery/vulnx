package vulnx

import "os/exec"

// killGroupOnCancel leaves cmd as it is: a host scan reads Linux and macOS, and on Windows runs no program.
func killGroupOnCancel(*exec.Cmd) {}
