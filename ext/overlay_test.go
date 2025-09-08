package ext

import (
	"testing"
)

func TestOverlay(t *testing.T) {
	f, err := CreateOverlay(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
}
