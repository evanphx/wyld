package main

import (
	"net"

	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/go-hclog"
	"github.com/lab47/wyld/dhcp6"
	"github.com/lab47/wyld/radvd"
	"github.com/vishvananda/netlink"
)

func main() {
	L := hclog.L()
	external := "eno1"
	internal := "enp1s0f0"

	_, err := netlink.LinkByName(external)
	if err != nil {
		panic(err)
	}

	il, err := netlink.LinkByName(internal)
	if err != nil {
		panic(err)
	}

	dh6, err := dhcp6.NewClient(dhcp6.ClientConfig{
		InterfaceName: external,
	})

	if err != nil {
		panic(err)
	}

	rad, err := radvd.NewServer()
	if err != nil {
		panic(err)
	}

	if dh6.ObtainOrRenew() {
		cfg := dh6.Config()

		spew.Dump(cfg)

		for _, prefix := range cfg.Prefixes {
			prefix.IP[len(prefix.IP)-1] = 1
			// Use the first /64 subnet within larger prefixes
			if ones, bits := prefix.Mask.Size(); ones < 64 {
				prefix.Mask = net.CIDRMask(64, bits)
			}

			addr, err := netlink.ParseAddr(prefix.String())
			if err != nil {
				panic(err)
			}

			L.Info("applying ipv6 address", "interface", internal, "address", prefix)

			if err := netlink.AddrAdd(il, addr); err != nil {
				L.Error("addr-replace error", "error", err, "addr", addr)
			}
		}

		L.Info("starting radvd", "interface", internal)
		rad.SetPrefixes(cfg.Prefixes)
		rad.ListenAndServe(internal)
	} else {
		L.Error("unable to get dhcp6 lease")
	}
}
