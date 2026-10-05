//go:build !(aix || darwin || dragonfly || freebsd || hurd || illumos || linux || netbsd || openbsd || solaris)

package workflow

import "os"

func tryLock(_ *os.File) error { return ErrLockUnsupported }

func unlock(_ *os.File) error { return nil }
