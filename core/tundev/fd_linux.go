//go:build linux && !android

package tundev

import (
	"fmt"
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

// FromFD wraps a descriptor for an interface that someone else created and
// configured -- an opened /dev/net/tun, for instance. Nothing is assigned
// here: the platform already brought the interface up.
func FromFD(fd, mtu int) (*Device, error) {
	if fd < 0 {
		return nil, fmt.Errorf("tundev: invalid tun fd %d", fd)
	}
	if mtu <= 0 {
		mtu = 1280
	}
	// CreateTUNFromFile takes ownership of the file on success; its failure
	// paths leave the file to the caller.
	f := os.NewFile(uintptr(fd), "p2p-tun")
	dev, err := tun.CreateTUNFromFile(f, mtu)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("tundev: from fd: %w", err)
	}
	return &Device{dev: dev, name: "p2p-tun", mtu: mtu}, nil
}
