//go:build !unix

package subprocess

import "os/exec"

func configureCancellation(cmd *exec.Cmd) {}
