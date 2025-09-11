//go:build wasip1

package x509

import (
	"encoding/json"
	"errors"
	"sync"
	"unsafe"

	crypto "github.com/goccy/wasi-go/ext/crypto/x509"
	"github.com/goccy/wasi-go/ext/wasip1/memory"
)

var (
	heap   = make(map[uint32][]byte)
	heapMu sync.Mutex
)

//go:wasmimport wasi_go_ext verify_certification
func verify_certification(uint32, uint32, uint32, uint32)

func VerifyCertification(dnsName string, leaf []byte, roots, intermediates [][]byte) error {
	b, err := json.Marshal(&crypto.VerifyOptions{
		DNSName:       dnsName,
		Leaf:          leaf,
		Roots:         roots,
		Intermediates: intermediates,
	})
	if err != nil {
		return err
	}
	out := make([]uint32, 2)
	outp := uint32(uintptr(unsafe.Pointer(&out[0])))
	verify_certification(
		uint32(uintptr(unsafe.Pointer(&b[0]))),
		uint32(len(b)),
		outp,
		outp+4,
	)
	if out[0] == 0 {
		return nil
	}
	e := unsafe.String((*byte)(unsafe.Pointer(uintptr(out[0]))), out[1])
	msg := make([]byte, out[1])
	copy(msg, []byte(e))
	memory.Free(out[0])
	return errors.New(string(msg))
}
