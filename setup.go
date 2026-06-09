package nat64ptr

import (
	"fmt"
	"net"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	nat64ptr, err := parse(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		nat64ptr.Next = next
		return nat64ptr
	})

	return nil
}

func parse(c *caddy.Controller) (*NAT64PTR, error) {
	var configured *NAT64PTR

	for c.Next() {
		args := c.RemainingArgs()
		if len(args) < 1 || len(args) > 3 {
			return nil, c.ArgErr()
		}

		ip, network, err := net.ParseCIDR(args[0])
		if err != nil {
			return nil, fmt.Errorf("invalid NAT64 prefix %q: %w", args[0], err)
		}

		if ip.To16() == nil || ip.To4() != nil {
			return nil, fmt.Errorf("NAT64 prefix must be an IPv6 CIDR: %q", args[0])
		}

		ones, bits := network.Mask.Size()
		if bits != 128 || ones != 96 {
			return nil, fmt.Errorf("NAT64 prefix must be /96: %q", args[0])
		}

		if configured != nil {
			return nil, fmt.Errorf("%s can only be configured once per server block", pluginName)
		}

		network.IP = ip.To16()
		configured = newNAT64PTR(network)
		if len(args) >= 2 {
			configured.setBackendSuffix(args[1])
		}
		if len(args) == 3 {
			configured.setPTRSuffix(args[2])
		}
	}

	if configured == nil {
		return nil, fmt.Errorf("missing NAT64 /96 prefix")
	}

	return configured, nil
}
