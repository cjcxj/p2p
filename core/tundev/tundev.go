// Package tundev wraps platform TUN virtual network devices. On Windows it
// requires wintun.dll (WireGuard's driver, placed next to the executable or
// on the system path); on Linux it uses /dev/net/tun (requires root).
package tundev

import (
	"fmt"
	"io"
	"net"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

// Device is a TUN virtual network interface.
type Device struct {
	dev   tun.Device
	name  string
	ip    net.IP
	mtu   int
}

// Create allocates a TUN device, assigns ip/mask and brings it up.
func Create(ip net.IP, mask net.IPMask, mtu int) (*Device, error) {
	if mtu <= 0 {
		mtu = 1500
	}
	dev, err := tun.CreateTUN("p2p%d", mtu)
	if err != nil {
		return nil, fmt.Errorf("tundev: create: %w (needs admin/root and, on Windows, wintun.dll)", err)
	}
	d := &Device{dev: dev, ip: ip, mtu: mtu}
	if n, ok := dev.(interface{ Name() (string, error) }); ok {
		if nm, err := n.Name(); err == nil && nm != "" && !strings.Contains(nm, "%") {
			d.name = nm
		}
	}
	if d.name == "" {
		d.name = "p2p-tun"
	}
	if err := configure(dev, ip, mask); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tundev: configure: %w", err)
	}
	return d, nil
}

// Name returns the OS interface name.
func (d *Device) Name() string { return d.name }

// Read reads a raw IP packet from the TUN device.
func (d *Device) Read(p []byte) (int, error) {
	sizes := make([]int, 1)
	n, err := d.dev.Read([][]byte{p}, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n < 1 {
		return 0, io.EOF
	}
	return sizes[0], nil
}

// Write writes a raw IP packet to the TUN device.
func (d *Device) Write(p []byte) (int, error) {
	return d.dev.Write([][]byte{p}, 0)
}

// Close closes the device.
func (d *Device) Close() error { return d.dev.Close() }

// IPv4Destination extracts the destination address of an IPv4 packet, or
// nil when the packet is not IPv4.
func IPv4Destination(pkt []byte) net.IP {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	return net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
}

// IsBroadcastOrMulticast reports whether an IP address needs broadcast
// handling in the virtual network.
func IsBroadcastOrMulticast(ip net.IP) bool {
	return ip.IsMulticast() || ip.Equal(net.IPv4bcast) || ip.IsUnspecified()
}

var _ io.ReadWriteCloser = (*Device)(nil)
