package ext

import (
	"context"

	"github.com/tetratelabs/wazero"

	crypto "github.com/goccy/wasi-go/ext/crypto/x509"
	"github.com/goccy/wasi-go/ext/os/exec"
)

func AddHostModule(ctx context.Context, r wazero.Runtime) error {
	host := r.NewHostModuleBuilder("wasi_go_ext")
	crypto.AddHostFunctions(host)
	exec.AddHostFunctions(host)
	if _, err := host.Instantiate(ctx); err != nil {
		return err
	}
	return nil
}
