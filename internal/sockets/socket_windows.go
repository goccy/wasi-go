//go:build windows

package sockets

import (
	"net/url"
	"syscall"
)

func Socket(_ string) (*url.URL, syscall.Sockaddr, int, error) {
	return nil, nil, -1, nil
}

func Close(_ int) error {
	return nil
}
