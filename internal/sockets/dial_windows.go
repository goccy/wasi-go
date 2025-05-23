//go:build windows

package sockets

func Dial(_ string) (int, error) {
	return 0, nil
}
