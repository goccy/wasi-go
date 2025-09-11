//go:build wasip1

package wasip1

import (
	_ "github.com/goccy/wasi-go/ext/wasip1/crypto/x509"
	_ "github.com/goccy/wasi-go/ext/wasip1/memory"
	_ "github.com/goccy/wasi-go/ext/wasip1/net"
	_ "github.com/goccy/wasi-go/ext/wasip1/os/exec"
)
