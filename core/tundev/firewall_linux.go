//go:build linux

package tundev

import (
	"fmt"
	"os/exec"
	"strings"
)

// AddInterfaceFirewallRules allows inbound/forwarded virtual-subnet traffic on
// the TUN interface. Many Linux cloud images run a default-drop INPUT policy
// (firewalld/iptables), which silently discards TCP/UDP packets injected into
// p2p0 even though the TUN itself is up.
func AddInterfaceFirewallRules(iface, subnet string) error {
	comment := "p2p-mesh-" + iface
	rules := [][]string{
		{"INPUT", "-i", iface, "-s", subnet, "-m", "comment", "--comment", comment, "-j", "ACCEPT"},
		{"FORWARD", "-i", iface, "-s", subnet, "-m", "comment", "--comment", comment, "-j", "ACCEPT"},
		{"FORWARD", "-o", iface, "-d", subnet, "-m", "comment", "--comment", comment, "-j", "ACCEPT"},
	}
	for _, rule := range rules {
		if err := iptablesInsertIfMissing(rule); err != nil {
			return err
		}
	}
	return nil
}

// RemoveInterfaceFirewallRules removes the rules added by
// AddInterfaceFirewallRules. Missing rules are ignored.
func RemoveInterfaceFirewallRules(iface string) error {
	comment := "p2p-mesh-" + iface
	// The actual subnet is not stored on the device, so delete by comment only.
	// iptables -D requires the full rule; use -S to find exact lines instead.
	out, err := exec.Command("iptables", "-S").CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables -S: %v: %s", err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, comment) {
			continue
		}
		// Convert "-A INPUT ..." to "-D INPUT ..." and run it.
		args := strings.Fields(trimmed)
		if len(args) < 2 || args[0] != "-A" {
			continue
		}
		args[0] = "-D"
		if err := exec.Command("iptables", args...).Run(); err != nil {
			return fmt.Errorf("iptables remove %s: %v", strings.Join(args, " "), err)
		}
	}
	return nil
}

func iptablesInsertIfMissing(rule []string) error {
	checkArgs := append([]string{"-C"}, rule...)
	if err := exec.Command("iptables", checkArgs...).Run(); err == nil {
		return nil // rule already exists
	}
	addArgs := append([]string{"-I"}, rule...)
	out, err := exec.Command("iptables", addArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables -I %s: %v: %s", strings.Join(rule, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
