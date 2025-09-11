package memory

import (
	"sync"
	"unsafe"
)

var (
	heap   = make(map[uint32][]byte)
	heapMu sync.Mutex
)

//go:wasmexport wasip1_alloc
func wasip1_alloc(size uint32) uint32 {
	if size == 0 {
		return 0
	}
	buf := make([]byte, size)
	p := uint32(uintptr(unsafe.Pointer(&buf[0])))
	heapMu.Lock()
	heap[p] = buf
	heapMu.Unlock()
	return p
}

func Free(p uint32) {
	heapMu.Lock()
	defer heapMu.Unlock()

	delete(heap, p)
}
