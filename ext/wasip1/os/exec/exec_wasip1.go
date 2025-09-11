package exec

import (
	"encoding/json"
	"os/exec"
	"unsafe"

	host "github.com/goccy/wasi-go/ext/os/exec"
	"github.com/goccy/wasi-go/ext/wasip1/memory"
)

//go:wasmimport wasi_go_ext start_command
func start_command(uint32, uint32, uint32, uint32)

func StartCommand(c *exec.Cmd) error {
	b, err := json.Marshal(&host.Cmd{
		Args:      c.Args,
		Env:       c.Env,
		Dir:       c.Dir,
		WaitDelay: c.WaitDelay,
	})
	if err != nil {
		return err
	}
	out := make([]uint32, 2)
	outp := uint32(uintptr(unsafe.Pointer(&out[0])))
	start_command(
		uint32(uintptr(unsafe.Pointer(&b[0]))),
		uint32(len(b)),
		outp,
		outp+4,
	)
	if out[0] == 0 {
		return nil
	}
	rawCmdOut := unsafe.String((*byte)(unsafe.Pointer(uintptr(out[0]))), out[1])
	newRawCmdOut := make([]byte, out[1])
	copy(newRawCmdOut, []byte(rawCmdOut))
	memory.Free(out[0])

	var cmdOut host.CmdOut
	if err := json.Unmarshal(newRawCmdOut, &cmdOut); err != nil {
		return err
	}
	if cmdOut.Err != nil {
		return cmdOut.Err
	}
	c.Stdout.Write(cmdOut.Stdout)
	c.Stderr.Write(cmdOut.Stderr)
	return nil
}
