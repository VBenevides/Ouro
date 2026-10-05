//go:build !(aix || darwin || dragonfly || freebsd || hurd || illumos || linux || netbsd || openbsd || solaris)

package process

import "os/exec"

func configureProcess(_ *exec.Cmd) {
	// No process-group configuration exists on this platform set.
}

func cancelProcess(command *exec.Cmd) error {
	if command.Process == nil {
		return nil
	}
	return command.Process.Kill()
}
