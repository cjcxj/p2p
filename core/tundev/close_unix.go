//go:build linux

package tundev

import "syscall"

// CloseFD releases a descriptor this package declined to take over. Android
// counts as Linux here, which is what the mobile path needs: the caller hands
// the VpnService descriptor over and must know it is closed either way.
func CloseFD(fd int) {
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
}
