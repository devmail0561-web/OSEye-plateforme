//go:build windows

package registry

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	modadvapi32reg              = windows.NewLazySystemDLL("advapi32.dll")
	procRegNotifyChangeKeyValue = modadvapi32reg.NewProc("RegNotifyChangeKeyValue")
)

// registryNotifyAsync arms an async RegNotifyChangeKeyValue with hEvent.
// When a matching change occurs, hEvent is signalled.
// Call windows.ResetEvent(hEvent) and re-arm after each notification.
func registryNotifyAsync(key registry.Key, watchSubtree bool, notifyFilter uint32, hEvent windows.Handle) error {
	var subtree uintptr
	if watchSubtree {
		subtree = 1
	}
	r, _, err := procRegNotifyChangeKeyValue.Call(
		uintptr(key),
		subtree,
		uintptr(notifyFilter),
		uintptr(hEvent), // hEvent — async mode
		1,               // bAsynchronous = TRUE
	)
	if r != 0 {
		return err
	}
	return nil
}
