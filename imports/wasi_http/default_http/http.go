package default_http

import (
	"context"

	"github.com/tetratelabs/wazero"

	"github.com/goccy/wasi-go/imports/wasi_http/types"
)

const ModuleName = "default-outgoing-HTTP"

func Instantiate(ctx context.Context, r wazero.Runtime, req *types.Requests, res *types.Responses, f *types.FieldsCollection) error {
	handler := &Handler{req, res, f}
	_, err := r.NewHostModuleBuilder(ModuleName).
		NewFunctionBuilder().WithFunc(requestFn).Export("request").
		NewFunctionBuilder().WithFunc(handler.handleFn).Export("handle").
		Instantiate(ctx)
	return err
}
