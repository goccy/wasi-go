package exec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type Cmd struct {
	Args      []string      `json:"args"`
	Env       []string      `json:"env"`
	Dir       string        `json:"dir"`
	WaitDelay time.Duration `json:"waitDelay"`
}

type CmdOut struct {
	Stdout []byte `json:"stdout"`
	Stderr []byte `json:"stderr"`
	Err    error  `json:"error"`
}

func AddHostFunctions(host wazero.HostModuleBuilder) {
	host.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			ptrAddr := api.DecodeU32(stack[2])
			lenAddr := api.DecodeU32(stack[3])
			b, _ := mod.Memory().Read(uint32(stack[0]), uint32(stack[1]))
			var cmd Cmd
			if err := json.Unmarshal(b, &cmd); err != nil {
				setOut(ctx, mod, &CmdOut{Err: err}, ptrAddr, lenAddr)
				return
			}
			setOut(ctx, mod, startCommand(&cmd), ptrAddr, lenAddr)
		}),
		[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("start_command")
}

func startCommand(c *Cmd) *CmdOut {
	var (
		stdout, stderr bytes.Buffer
	)
	cmd := exec.Command(c.Args[0], c.Args[1:]...)
	cmd.Env = c.Env
	cmd.Dir = c.Dir
	cmd.WaitDelay = c.WaitDelay
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return &CmdOut{Err: err}
	}
	return &CmdOut{
		Stdout: stdout.Bytes(),
		Stderr: stderr.Bytes(),
	}
}

func setOut(ctx context.Context, mod api.Module, out *CmdOut, ptrAddr, lenAddr uint32) {
	b, err := json.Marshal(out)
	if err != nil {
		panic(err)
	}
	alloc := mod.ExportedFunction("wasip1_alloc")
	if alloc == nil {
		panic("failed to find wasip1_alloc exported function")
	}
	res, err := alloc.Call(ctx, uint64(len(b)))
	if err != nil {
		panic(err)
	}
	ptr := uint32(res[0])
	if ok := mod.Memory().Write(ptr, b); !ok {
		panic(fmt.Sprintf("wasi-go.start_command: failed to write: %q", b))
	}
	_ = mod.Memory().WriteUint32Le(ptrAddr, ptr)
	_ = mod.Memory().WriteUint32Le(lenAddr, uint32(len(b)))
}
