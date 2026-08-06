//go:build linux

package udev

import "unsafe"

func unsafePtr(b *byte) unsafe.Pointer {
	return unsafe.Pointer(b)
}
