package default_http

import (
	"context"
	"log"

	"github.com/tetratelabs/wazero/api"

	"github.com/goccy/wasi-go/imports/wasi_http/types"
)

type Handler struct {
	req *types.Requests
	res *types.Responses
	f   *types.FieldsCollection
}

// Request handles HTTP serving. It's currently unimplemented
func requestFn(_ context.Context, mod api.Module, a, b, c, d, e, f, g, h, j, k, l, m, n, o uint32) int32 {
	return 0
}

// Handle handles HTTP client calls.
// The remaining parameters (b..h) are for the HTTP Options, currently unimplemented.
func (handler *Handler) handleFn(_ context.Context, mod api.Module, request, b, c, d, e, f, g, h uint32) uint32 {
	req, ok := handler.req.GetRequest(request)
	if !ok {
		log.Printf("Failed to get request: %v\n", request)
		return 0
	}
	r, err := req.MakeRequest(handler.f)
	if err != nil {
		log.Println(err.Error())
		return 0
	}
	return handler.res.MakeResponse(r)
}
