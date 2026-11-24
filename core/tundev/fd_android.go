//go:build android

package tundev

import (
	"fmt"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
)

// FromFD wraps the descriptor a VpnService established for us. The interface
// and its address already exist -- Android created them -- so this only hands
// the descriptor to a WireGuard interface. The descriptor is not monitored
// through netlink, which is how Android's tun differs from Linux's.
//
// FromFD owns fd: every path, including the failing ones, leaves the descriptor
// closed, so callers must not close it again after passing it in.
func FromFD(fd, mtu int) (*Device, error) {
	if fd < 0 {
		return nil, fmt.Errorf("tundev: invalid tun fd %d", fd)
	}
	if mtu <= 0 {
		mtu = 1280
	}
	dev, name, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		// WireGuard's constructor returns the descriptor still open on failure.
		syscall.Close(fd)
		return nil, fmt.Errorf("tundev: from fd: %w", err)
	}
	if name == "" {
		name = "p2p-tun"
	}
	return &Device{dev: fixedMTU{dev, mtu}, name: name, mtu: mtu}, nil
}

// fixedMTU answers with the MTU the VpnService was configured with instead of
// asking the kernel. WireGuard wants the value from the device before it starts,
// and the only way its Linux implementation can get one is an interface-name
// ioctl -- which an unprivileged Android app is not guaranteed to be allowed to
// issue on the tunnel it was just handed.
type fixedMTU struct {
	tun.Device
	mtu int
}

func (d fixedMTU) MTU() (int, error) { return d.mtu, nil }
