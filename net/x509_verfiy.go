package net

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type VerifyOptions struct {
	Leaf          []byte   `json:"leaf"`
	Roots         [][]byte `json:"roots"`
	Intermediates [][]byte `json:"intermediates"`
	DNSName       string   `json:"dnsName"`
}

func addVerifyCertification(host wazero.HostModuleBuilder) {
	host.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			ptrAddr := api.DecodeU32(stack[2])
			lenAddr := api.DecodeU32(stack[3])
			b, _ := mod.Memory().Read(uint32(stack[0]), uint32(stack[1]))
			var opts VerifyOptions
			if err := json.Unmarshal(b, &opts); err != nil {
				setError(ctx, mod, err, ptrAddr, lenAddr)
				return
			}
			if err := systemVerify(&opts); err != nil {
				setError(ctx, mod, err, ptrAddr, lenAddr)
				return
			}
			_ = mod.Memory().WriteUint32Le(ptrAddr, 0)
			_ = mod.Memory().WriteUint32Le(lenAddr, 0)
		}),
		[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("verify_certification")
}

func systemVerify(opts *VerifyOptions) error {
	leaf, err := x509.ParseCertificate(opts.Leaf)
	if err != nil {
		return err
	}
	var (
		roots, intermediates *x509.CertPool
	)
	if len(opts.Roots) != 0 {
		roots = x509.NewCertPool()
	}
	if len(opts.Intermediates) != 0 {
		intermediates = x509.NewCertPool()
	}
	for _, root := range opts.Roots {
		c, err := x509.ParseCertificate(root)
		if err != nil {
			continue
		}
		roots.AddCert(c)
	}
	for _, in := range opts.Intermediates {
		c, err := x509.ParseCertificate(in)
		if err != nil {
			continue
		}
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       opts.DNSName,
		Roots:         roots,
		Intermediates: intermediates,
	}); err != nil {
		return fmt.Errorf("failed to verify: %w", err)
	}
	return nil
}

func setError(ctx context.Context, mod api.Module, err error, ptrAddr, lenAddr uint32) {
	alloc := mod.ExportedFunction("wasip1_alloc")
	if alloc == nil {
		panic("failed to find wasip1_alloc exported function")
	}
	e := err.Error()
	res, err := alloc.Call(ctx, uint64(len(e)))
	if err != nil {
		panic(err)
	}
	ptr := uint32(res[0])
	if ok := mod.Memory().WriteString(ptr, e); !ok {
		panic(fmt.Sprintf("wasi-go.verify_certification: failed to write: %s", e))
	}
	_ = mod.Memory().WriteUint32Le(ptrAddr, ptr)
	_ = mod.Memory().WriteUint32Le(lenAddr, uint32(len(e)))
}
