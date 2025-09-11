//go:build !windows

package ext_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tetratelabs/wazero"

	"github.com/goccy/wasi-go/ext"
	"github.com/goccy/wasi-go/imports"
)

func TestExt(t *testing.T) {
	ctx := t.Context()
	overlayFile, err := ext.CreateOverlay(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer overlayFile.Close()

	cmd := exec.Command(
		"go", "build",
		"-buildmode=c-shared",
		"-overlay", overlayFile.Path(),
		"-o", "testdata/plugin.wasm",
		"testdata/main.go",
	)
	cmd.Env = append(os.Environ(), []string{
		"GOOS=wasip1",
		"GOARCH=wasm",
	}...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v", string(out), err)
	}
	path := filepath.Join("testdata", "plugin.wasm")
	wasmFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rcfg := wazero.NewRuntimeConfigInterpreter().
		WithCloseOnContextDone(true)

	r := wazero.NewRuntimeWithConfig(ctx, rcfg)
	compiledMod, err := r.CompileModule(ctx, wasmFile)
	if err != nil {
		t.Fatal(err)
	}
	modCfg := wazero.NewModuleConfig().
		WithStdin(os.Stdin).
		WithStdout(os.Stdout).
		WithStderr(os.Stderr).
		WithFSConfig(wazero.NewFSConfig().WithFSMount(os.DirFS("/"), "")).
		WithStartFunctions("_initialize")

	ctx, sys, err := imports.NewBuilder().
		WithSocketsExtension("wasmedgev2", compiledMod).
		WithWasiGoExtension().
		WithStdio(int(os.Stdin.Fd()), int(os.Stdout.Fd()), int(os.Stderr.Fd())).
		WithDirs("/").
		Instantiate(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	_ = sys

	api, err := r.InstantiateModule(
		ctx, compiledMod, modCfg,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("http", func(t *testing.T) {
		fn := api.ExportedFunction("testHTTP")
		if fn == nil {
			t.Fatal("could not find testHTTP function")
		}
		if _, err := fn.Call(ctx); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("exec", func(t *testing.T) {
		fn := api.ExportedFunction("testExec")
		if fn == nil {
			t.Fatal("could not find testExec function")
		}
		if _, err := fn.Call(ctx); err != nil {
			t.Fatal(err)
		}
	})
}
