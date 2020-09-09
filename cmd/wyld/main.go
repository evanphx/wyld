package main

import (
	"encoding/json"
	"net"
	"os"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/go-hclog"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/lab47/wyld/dhcp6"
	"github.com/lab47/wyld/dnsforward"
	"github.com/lab47/wyld/radvd"
	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type config struct {
	L hclog.Logger

	External, Internal string

	DHCP6Path string

	XL, IL netlink.Link
}

func main() {
	external := "eno1"
	internal := "enp1s0f0"

	xl, err := netlink.LinkByName(external)
	if err != nil {
		panic(err)
	}

	il, err := netlink.LinkByName(internal)
	if err != nil {
		panic(err)
	}

	l := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	cfg := config{
		L:         l,
		External:  external,
		Internal:  internal,
		XL:        xl,
		IL:        il,
		DHCP6Path: "./dhcp6-lease.json",
	}

	go dnsfwd(&cfg)
	go ipv6(&cfg)

	select {}
}

func dnsfwd(c *config) {
	s, err := dnsforward.NewServer("10.0.1.1:53", "c.phx.io", dnsforward.DefaultUpstreams)
	if err != nil {
		panic(err)
	}

	serv := &dns.Server{
		Addr:    net.JoinHostPort("10.0.1.1", "53"),
		Net:     "udp",
		Handler: s.Mux,
	}

	c.L.Info("starting DNS server...")

	serv.ListenAndServe()
}

type dhcp6LeaseFile struct {
	Config    dhcp6.Config `json:"dhcp6"`
	WrittenAt time.Time    `json:"written_at"`
}

func saveConfig(path string, data interface{}) {
	f, err := os.Create(path)
	if err != nil {
		return
	}

	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.Encode(data)
}

func ipv6(c *config) {
	var lf dhcp6LeaseFile

	if f, err := os.Open(c.DHCP6Path); err == nil {
		err = json.NewDecoder(f).Decode(&lf)
		if err != nil {
			panic(err)
		}
		spew.Dump(lf)
	}

	if lf.Config.DUID == nil {
		iface, err := net.InterfaceByName(c.External)
		if err != nil {
			panic(err)
		}

		duid := &dhcpv6.Duid{
			Type:          dhcpv6.DUID_LLT,
			HwType:        iana.HWTypeEthernet,
			Time:          dhcpv6.GetTime(),
			LinkLayerAddr: iface.HardwareAddr,
		}

		lf.Config.DUID = duid.ToBytes()
	}

	dh6, err := dhcp6.NewClient(dhcp6.ClientConfig{
		Logger:        c.L,
		InterfaceName: c.External,
		CurrentConfig: lf.Config,
	})
	if err != nil {
		panic(err)
	}

	rad, err := radvd.NewServer()
	if err != nil {
		panic(err)
	}

	var runningRad bool

	for {
		for !dh6.ObtainOrRenew() {
			c.L.Error("error getting address details, retrying")
			time.Sleep(30 * time.Second)
		}

		cfg := dh6.Config()

		saveConfig(c.DHCP6Path, &dhcp6LeaseFile{
			WrittenAt: time.Now(),
			Config:    cfg,
		})

		current, err := netlink.AddrList(c.XL, unix.AF_INET6)
		if err != nil {
			panic(err)
		}

		seen := map[string]netlink.Addr{}

		for _, addr := range current {
			seen[addr.IP.String()] = addr
		}

		var toAdd []string

		for _, addr := range cfg.Addresses {
			if _, ok := seen[addr.String()]; !ok {
				toAdd = append(toAdd, addr.String())
			}
		}

		for _, k := range toAdd {
			v, err := netlink.ParseAddr(k + "/128")
			if err != nil {
				panic(err)
			}

			c.L.Info("adding address to external interface", "addr", k)
			netlink.AddrAdd(c.XL, v)
		}

		for _, addr := range cfg.OldAddresses {
			na, err := netlink.ParseAddr(addr.String() + "/128")
			if err != nil {
				panic(err)
			}

			c.L.Info("removing old address on external interface", "addr", addr.String())
			netlink.AddrDel(c.XL, na)
		}

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

			c.L.Info("applying ipv6 address", "interface", c.Internal, "address", prefix.String())

			var skip bool

			for _, cur := range current {
				if cur.IP.Equal(prefix.IP) {
					skip = true
					break
				}
			}

			if skip {
				c.L.Info("found interface already had address")
			} else {
				if err := netlink.AddrReplace(c.IL, addr); err != nil {
					c.L.Error("addr-replace error", "error", err, "addr", addr)
				}
			}
		}

		if !runningRad {
			runningRad = true
			c.L.Info("starting radvd", "interface", c.Internal)
			rad.SetPrefixes(cfg.Prefixes)
			go rad.ListenAndServe(c.Internal)
		}

		renewIn := time.Until(cfg.RenewAfter) / 2

		c.L.Info("waiting to renew dhcpv6 lease", "timeout", renewIn.String())

		time.Sleep(renewIn)
	}
}
