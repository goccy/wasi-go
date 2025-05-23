//go:build windows

package wasi

import "syscall"

func syscallErrnoToWASI(err syscall.Errno) Errno {
	return 0
}
