//go:build wasip1

package net

import (
	"context"
	"net"

	"github.com/goccy/wasi-go-net/wasip1"
)

func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return wasip1.DialContext(ctx, network, address)
}

func Listen(network, address string) (net.Listener, error) {
	return wasip1.Listen(network, address)
}
