//go:build !linux

package tundev

import "fmt"

// FromFD wraps a TUN descriptor created elsewhere. Only platforms with a
// descriptor-based tunnel (Android's VpnService, Linux's /dev/net/tun) can
// hand one out; here the concept does not exist.
func FromFD(fd, mtu int) (*Device, error) {
	return nil, fmt.Errorf("tundev: attaching an existing tun fd is not supported on this platform")
}

// CloseFD is a no-op here: no platform in this build tag passes a descriptor
// that the package could have opened or taken ownership of.
func CloseFD(fd int) {}
