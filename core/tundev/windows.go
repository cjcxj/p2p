//go:build windows

package tundev

import (
	"fmt"
	"net"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"
)

// configure assigns the address and brings the interface up on Windows using
// netsh (requires Administrator).
func configure(dev tun.Device, ip net.IP, mask net.IPMask) error {
	name, err := dev.Name()
	if err != nil {
		return err
	}
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "address",
		"name="+name, "source=static", "addr="+ip.String(), "mask="+maskString(mask))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh: %v: %s", err, out)
	}
	return nil
}

func maskString(m net.IPMask) string {
	if len(m) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
	}
	// derive the dotted mask from the prefix length
	ones, _ := m.Size()
	im := net.CIDRMask(ones, 32)
	return fmt.Sprintf("%d.%d.%d.%d", im[0], im[1], im[2], im[3])
}
