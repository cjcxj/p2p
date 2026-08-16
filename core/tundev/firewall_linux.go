//go:build !windows

package tundev

// AddInterfaceFirewallRules is a no-op on non-Windows platforms (firewall
// rules are a Windows-specific workaround for the default inbound policy).
func AddInterfaceFirewallRules(iface, subnet string) error { return nil }

// RemoveInterfaceFirewallRules is a no-op on non-Windows platforms.
func RemoveInterfaceFirewallRules(iface string) error { return nil }
