//go:build windows

package registry

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"unsafe"
)

var (
	modadvapi32reg          = windows.NewLazySystemDLL("advapi32.dll")
	procRegNotifyChangeKeyValue = modadvapi32reg.NewProc("RegNotifyChangeKeyValue")
)

// registryNotify wraps RegNotifyChangeKeyValue.
// watchSubtree=true monitors sub-keys too; async=false blocks until change detected.
func registryNotify(key registry.Key, watchSubtree bool, notifyFilter uint32, async bool) error {
	var subtree, asyncInt uintptr
	if watchSubtree {
		subtree = 1
	}
	if async {
		asyncInt = 1
	}
	r, _, err := procRegNotifyChangeKeyValue.Call(
		uintptr(key),
		subtree,
		uintptr(notifyFilter),
		0, // hEvent = NULL (synchronous)
		asyncInt,
	)
	if r != 0 {
		// Non-zero return = error
		_ = unsafe.Pointer(nil) // keep import used
		return err
	}
	return nil
}
