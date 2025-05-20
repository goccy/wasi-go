//go:build wasip1

package wasi

import "syscall"

func syscallErrnoToWASI(err syscall.Errno) Errno {
	return 0
}
