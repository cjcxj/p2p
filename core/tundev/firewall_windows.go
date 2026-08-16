//go:build windows

// Package tundev firewall support: adds Windows Firewall rules scoped to a
// specific network interface so that inbound ICMP/TCP/UDP from the virtual
// subnet is not dropped by the default Public-profile policy. Mirrors what
// EasyTier does (interface-scoped allow rules for TCP/UDP/ICMP/ALL).
package tundev

import (
	"fmt"
	"os/exec"
	"strings"
)

// ruleName builds a unique, stable rule name for the given interface,
// protocol and direction.
func ruleName(iface, proto, dir string) string {
	return fmt.Sprintf("p2p %s - %s Protocol (%s)", iface, proto, dir)
}

// AddInterfaceFirewallRules adds inbound+outbound allow rules for TCP, UDP,
// ICMPv4 and all protocols, scoped to the virtual subnet (netsh supports no
// interface= parameter for advfirewall; scope by remoteip instead). Requires
// administrator privileges; a non-nil error is returned if a rule could not
// be created.
func AddInterfaceFirewallRules(iface, subnet string) error {
	for _, proto := range []string{"ICMPv4", "TCP", "UDP", "ANY"} {
		if err := addRule(iface, subnet, proto, true); err != nil {
			return err
		}
		if err := addRule(iface, subnet, proto, false); err != nil {
			return err
		}
	}
	return nil
}

func addRule(iface, subnet, proto string, inbound bool) error {
	dir := "out"
	dirName := "Outbound"
	if inbound {
		dir = "in"
		dirName = "Inbound"
	}
	name := ruleName(iface, proto, dirName)
	args := []string{
		"advfirewall", "firewall", "add", "rule",
		"name=" + name,
		"dir=" + dir,
		"action=allow",
		"enable=yes",
		"profile=any",
		"remoteip=" + subnet,
	}
	if proto != "ANY" {
		args = append(args, "protocol="+proto)
	}
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh add rule %s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RemoveInterfaceFirewallRules deletes the rules created by
// AddInterfaceFirewallRules for the named interface. Errors are returned
// only if the netsh invocation itself fails; a missing rule is not an error.
func RemoveInterfaceFirewallRules(iface string) error {
	for _, proto := range []string{"ICMPv4", "TCP", "UDP", "ANY"} {
		for _, dirName := range []string{"Inbound", "Outbound"} {
			name := ruleName(iface, proto, dirName)
			out, err := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
				"name="+name).CombinedOutput()
			if err != nil {
				return fmt.Errorf("netsh delete rule %s: %v: %s", name, err, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}
