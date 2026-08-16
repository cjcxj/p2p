//go:build linux

package tundev

import (
	"fmt"
	"net"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"
)

// configure assigns the address and brings the interface up on Linux.
func configure(dev tun.Device, ip net.IP, mask net.IPMask) error {
	name, err := dev.Name()
	if err != nil {
		return err
	}
	ones, _ := mask.Size()
	prefix := fmt.Sprintf("%s/%d", ip.String(), ones)
	for _, a := range [][]string{
		{"link", "set", "dev", name, "up"},
		{"addr", "add", prefix, "dev", name},
	} {
		if err := runIP(a...); err != nil {
			return err
		}
	}
	return nil
}

func runIP(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %v: %v: %s", args, err, out)
	}
	return nil
}
