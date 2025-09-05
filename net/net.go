package net

import (
	"context"

	"github.com/tetratelabs/wazero"
)

func AddHostModule(ctx context.Context, r wazero.Runtime) error {
	host := r.NewHostModuleBuilder("wasi_go_net")
	addVerifyCertification(host)
	if _, err := host.Instantiate(ctx); err != nil {
		return err
	}
	return nil
}
