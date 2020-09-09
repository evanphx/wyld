// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package dhcp6 implements a DHCPv6 client.
package dhcp6

import (
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/go-hclog"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/client6"
	"github.com/insomniacslk/dhcp/iana"
)

type ClientConfig struct {
	Logger hclog.Logger

	InterfaceName string // e.g. eth0

	// LocalAddr allows overwriting the source address used for sending DHCPv6
	// packets. It defaults to the first link-local address of InterfaceName.
	LocalAddr *net.UDPAddr

	// RemoteAddr allows addressing a specific DHCPv6 server. It defaults to
	// the dhcpv6.AllDHCPRelayAgentsAndServers multicast address.
	RemoteAddr *net.UDPAddr

	// DUID contains all bytes (including the prefixing uint16 type field) for a
	// DHCP Unique Identifier (e.g. []byte{0x00, 0x0a, 0x00, 0x03, 0x00, 0x01,
	// 0x4c, 0x5e, 0xc, 0x41, 0xbf, 0x39}).
	//
	// Fiber7 assigns static IPv6 /48 networks to DUIDs, so it is important to
	// be able to carry it around between devices.
	DUID []byte

	Conn           net.PacketConn         // for testing
	TransactionIDs []dhcpv6.TransactionID // for testing

	// HardwareAddr allows overriding the hardware address in tests. If nil,
	// defaults to the hardware address of the interface identified by
	// InterfaceName.
	HardwareAddr net.HardwareAddr

	// Configuration previously retrieved
	CurrentConfig Config
}

// Config contains the obtained network configuration.
type Config struct {
	RenewAfter   time.Time   `json:"valid_until"`
	Addresses    []net.IP    `json:"addresses"`     // IANA or IATA addresses
	OldAddresses []net.IP    `json:"old_addresses"` // IANA or IATA addresses
	Prefixes     []net.IPNet `json:"prefixes"`      // e.g. 2a02:168:4a00::/48
	OldPrefixes  []net.IPNet `json:"old_prefixes"`
	DNS          []string    `json:"dns"` // e.g. 2001:1620:2777:1::10, 2001:1620:2777:2::20
	DUID         []byte      `json:"duid"`
	ServerId     []byte      `json:"server_id"`
}

type Client struct {
	log           hclog.Logger
	interfaceName string
	hardwareAddr  net.HardwareAddr
	raddr         *net.UDPAddr
	timeNow       func() time.Time
	duid          *dhcpv6.Duid
	advertise     *dhcpv6.Message

	cfg Config
	err error

	Conn net.PacketConn // TODO: unexport

	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	RemoteAddr net.Addr
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Logger == nil {
		cfg.Logger = hclog.L()
	}

	iface, err := net.InterfaceByName(cfg.InterfaceName)
	if err != nil {
		return nil, err
	}

	// if no LocalAddr is specified, get the interface's link-local address
	laddr := cfg.LocalAddr
	if laddr == nil {
		llAddr, err := dhcpv6.GetLinkLocalAddr(cfg.InterfaceName)
		if err != nil {
			return nil, err
		}
		laddr = &net.UDPAddr{
			IP:   llAddr,
			Port: dhcpv6.DefaultClientPort,
			// HACK: Zone should ideally be cfg.InterfaceName, but Go’s
			// ipv6ZoneCache is only updated every 60s, so the addition of the
			// veth interface will not be picked up for all tests after the
			// first test.
			Zone: strconv.Itoa(iface.Index),
		}
	}

	// if no RemoteAddr is specified, use AllDHCPRelayAgentsAndServers
	raddr := cfg.RemoteAddr
	if raddr == nil {
		raddr = &net.UDPAddr{
			IP:   dhcpv6.AllDHCPRelayAgentsAndServers,
			Port: dhcpv6.DefaultServerPort,
		}
	}

	hardwareAddr := iface.HardwareAddr
	if cfg.HardwareAddr != nil {
		hardwareAddr = cfg.HardwareAddr
	}

	var duid *dhcpv6.Duid

	if cfg.CurrentConfig.DUID != nil {
		duid, err = dhcpv6.DuidFromBytes(cfg.CurrentConfig.DUID)
		if err != nil {
			return nil, err
		}
	} else if cfg.DUID != nil {
		duid, err = dhcpv6.DuidFromBytes(cfg.DUID)
		if err != nil {
			return nil, err
		}
	} else {
		duid = &dhcpv6.Duid{
			Type:          dhcpv6.DUID_LL,
			HwType:        iana.HWTypeEthernet,
			LinkLayerAddr: hardwareAddr,
		}
	}

	cfg.Logger.Debug("Calculated DUID", "duid", hclog.Fmt("%+v", duid))

	// prepare the socket to listen on for replies
	conn := cfg.Conn
	if conn == nil {
		udpConn, err := net.ListenUDP("udp6", laddr)
		if err != nil {
			return nil, err
		}
		conn = udpConn
	}

	return &Client{
		log:           cfg.Logger,
		cfg:           cfg.CurrentConfig,
		interfaceName: cfg.InterfaceName,
		hardwareAddr:  hardwareAddr,
		timeNow:       time.Now,
		raddr:         raddr,
		Conn:          conn,
		duid:          duid,
		ReadTimeout:   client6.DefaultReadTimeout,
		WriteTimeout:  client6.DefaultWriteTimeout,
	}, nil
}

func (c *Client) Close() error {
	return c.Conn.Close()
}

const maxUDPReceivedPacketSize = 8192 // arbitrary size. Theoretically could be up to 65kb

func (c *Client) sendReceive(packet *dhcpv6.Message, expectedType dhcpv6.MessageType) (*dhcpv6.Message, error) {
	if packet == nil {
		return nil, fmt.Errorf("packet to send cannot be nil")
	}
	if expectedType == dhcpv6.MessageTypeNone {
		// infer the expected type from the packet being sent
		if packet.Type() == dhcpv6.MessageTypeSolicit {
			expectedType = dhcpv6.MessageTypeAdvertise
		} else if packet.Type() == dhcpv6.MessageTypeRequest {
			expectedType = dhcpv6.MessageTypeReply
		} else if packet.Type() == dhcpv6.MessageTypeRenew {
			expectedType = dhcpv6.MessageTypeReply
		} else if packet.Type() == dhcpv6.MessageTypeRelease {
			expectedType = dhcpv6.MessageTypeReply
		} else if packet.Type() == dhcpv6.MessageTypeRelayForward {
			expectedType = dhcpv6.MessageTypeRelayReply
		} else if packet.Type() == dhcpv6.MessageTypeLeaseQuery {
			expectedType = dhcpv6.MessageTypeLeaseQueryReply
		} // and probably more
	}

	// send the packet out
	c.Conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	if _, err := c.Conn.WriteTo(packet.ToBytes(), c.raddr); err != nil {
		return nil, err
	}

	// wait for a reply
	c.Conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	var (
		adv *dhcpv6.Message
	)
	for {
		buf := make([]byte, maxUDPReceivedPacketSize)
		n, _, err := c.Conn.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		adv, err = dhcpv6.MessageFromBytes(buf[:n])
		if err != nil {
			log.Printf("non-DHCP: %v", err)
			// skip non-DHCP packets
			continue
		}
		if packet.TransactionID != adv.TransactionID {
			log.Printf("different XID: got %v, want %v", adv.TransactionID, packet.TransactionID)
			// different XID, we don't want this packet for sure
			continue
		}
		if expectedType == dhcpv6.MessageTypeNone {
			// just take whatever arrived
			break
		} else if adv.MessageType == expectedType {
			break
		}
	}
	return adv, nil
}

func (c *Client) Release() (*dhcpv6.Message, error) {
	var err error
	msg, err := dhcpv6.NewMessage()
	if err != nil {
		return nil, err
	}
	msg.MessageType = dhcpv6.MessageTypeRelease
	msg.AddOption(dhcpv6.OptClientID(*c.duid))
	msg.AddOption(dhcpv6.OptElapsedTime(0))

	id := c.iaid()

	iana := &dhcpv6.OptIANA{}
	copy(iana.IaId[:], id[:])

	for _, i := range c.cfg.Addresses {
		iana.Options.Add(&dhcpv6.OptIAAddress{
			IPv6Addr: i,
		})
	}

	msg.UpdateOption(iana)

	iapd := &dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, 1}}

	for _, i := range c.cfg.Prefixes {
		pf := i
		iapd.Options.Add(&dhcpv6.OptIAPrefix{
			Prefix: &pf,
		})
	}

	msg.UpdateOption(iapd)

	if len(c.cfg.ServerId) > 0 {
		sid, err := dhcpv6.DuidFromBytes(c.cfg.ServerId)
		if err == nil {
			msg.AddOption(dhcpv6.OptServerID(*sid))
		}
	}

	c.log.Trace("performing release operation", "msg", msg.Summary(), "prefixes", spew.Sdump(c.cfg.Prefixes), "sid", c.cfg.ServerId)
	reply, err := c.sendReceive(msg, dhcpv6.MessageTypeNone)
	return reply, err
}

func (c *Client) iaid() [4]byte {
	h := fnv.New32()
	h.Write(c.hardwareAddr)

	var iaid [4]byte
	copy(iaid[:], h.Sum(nil))
	return iaid
}

func (c *Client) renew() (*dhcpv6.Message, error) {
	var err error
	msg, err := dhcpv6.NewMessage()
	if err != nil {
		return nil, err
	}
	msg.MessageType = dhcpv6.MessageTypeRenew
	msg.AddOption(dhcpv6.OptClientID(*c.duid))
	msg.AddOption(dhcpv6.OptElapsedTime(0))

	id := c.iaid()

	iana := &dhcpv6.OptIANA{}
	copy(iana.IaId[:], id[:])

	for _, i := range c.cfg.Addresses {
		iana.Options.Add(&dhcpv6.OptIAAddress{
			IPv6Addr: i,
		})
	}

	msg.AddOption(iana)

	iapd := &dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, 1}}

	for _, i := range c.cfg.Prefixes {
		pf := i
		iapd.Options.Add(&dhcpv6.OptIAPrefix{
			Prefix: &pf,
		})
	}

	msg.AddOption(iapd)

	if len(c.cfg.ServerId) > 0 {
		sid, err := dhcpv6.DuidFromBytes(c.cfg.ServerId)
		if err == nil {
			msg.AddOption(dhcpv6.OptServerID(*sid))
		}
	}

	c.log.Trace("performing renew operation", "msg", msg.Summary(), "prefixes", spew.Sdump(c.cfg.Prefixes), "sid", c.cfg.ServerId)
	reply, err := c.sendReceive(msg, dhcpv6.MessageTypeNone)
	return reply, err
}

func (c *Client) solicit(solicit *dhcpv6.Message) (*dhcpv6.Message, *dhcpv6.Message, error) {
	var err error
	if solicit == nil {
		solicit, err = dhcpv6.NewSolicit(c.hardwareAddr, dhcpv6.WithClientID(*c.duid))
		if err != nil {
			return nil, nil, err
		}
	}

	iapd := &dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, 1}}

	for _, prefix := range c.cfg.Prefixes {
		pf := prefix
		iapd.Options.Add(&dhcpv6.OptIAPrefix{
			Prefix: &pf,
		})
	}

	solicit.AddOption(iapd)
	advertise, err := c.sendReceive(solicit, dhcpv6.MessageTypeNone)
	return solicit, advertise, err
}

func (c *Client) request(advertise *dhcpv6.Message) (*dhcpv6.Message, *dhcpv6.Message, error) {
	request, err := dhcpv6.NewRequestFromAdvertise(advertise, dhcpv6.WithClientID(*c.duid))
	if err != nil {
		return nil, nil, err
	}

	if iapd := advertise.Options.OneIAPD(); iapd != nil {
		request.AddOption(iapd)
	}

	reply, err := c.sendReceive(request, dhcpv6.MessageTypeNone)
	return request, reply, err
}

func (c *Client) ObtainOrRenew() bool {
	c.err = nil // clear previous error

	var (
		reply *dhcpv6.Message
		err   error
	)

	spew.Dump(c.cfg)

	if len(c.cfg.Prefixes) > 0 || len(c.cfg.Addresses) > 0 {
		c.log.Debug("Sending renew request...")
		reply, err = c.renew()
		if err == nil {
			c.log.Debug("reply from server", "summary", reply.Summary())
		} else {
			c.log.Info("error sending renew, proceding with new address", "error", err)
		}

		if iapd := reply.Options.OneIAPD(); iapd != nil {
			if status := iapd.Options.Status(); status != nil && status.StatusCode != iana.StatusSuccess {
				c.log.Error("error reported with renewing IAPD", "status", status.StatusCode.String(), "message", status.StatusMessage)
				c.log.Info("renew failed, getting new addresses")
				reply = nil
			}
		}
	}

	if reply == nil {
		c.log.Debug("soliciting address")

		_, advertise, err := c.solicit(nil)
		if err != nil {
			c.err = err
			return true
		}

		c.advertise = advertise

		if iapd := advertise.Options.OneIAPD(); iapd != nil {
			if status := iapd.Options.Status(); status != nil && status.StatusCode != iana.StatusSuccess {
				c.err = fmt.Errorf("IAPD error: %v (%v)", status.StatusCode, status.StatusMessage)
				return false
			}
		}

		_, reply, err = c.request(advertise)
		if err != nil {
			c.err = err
			return true
		}
	}

	sid := reply.Options.ServerID()

	c.log.Debug("reply from server", "summary", reply.Summary(), "sid", spew.Sdump(sid))

	var newCfg Config
	newCfg.DUID = c.duid.ToBytes()
	newCfg.ServerId = sid.ToBytes()

	for _, iana := range reply.Options.IANA() {
		t1 := c.timeNow().Add(iana.T1)
		if t1.Before(newCfg.RenewAfter) || newCfg.RenewAfter.IsZero() {
			newCfg.RenewAfter = t1
		}

		for _, addr := range iana.Options.Addresses() {
			if addr.ValidLifetime > 0 {
				newCfg.Addresses = append(newCfg.Addresses, addr.IPv6Addr)
			} else {
				newCfg.OldAddresses = append(newCfg.OldAddresses, addr.IPv6Addr)
			}
		}
	}

	for _, iapd := range reply.Options.IAPD() {
		t1 := c.timeNow().Add(iapd.T1)
		if t1.Before(newCfg.RenewAfter) || newCfg.RenewAfter.IsZero() {
			newCfg.RenewAfter = t1
		}

		for _, prefix := range iapd.Options.Prefixes() {
			if prefix.ValidLifetime > 0 {
				newCfg.Prefixes = append(newCfg.Prefixes, *prefix.Prefix)
			} else {
				newCfg.OldPrefixes = append(newCfg.OldPrefixes, *prefix.Prefix)
			}
		}
	}

	for _, dns := range reply.Options.DNS() {
		newCfg.DNS = append(newCfg.DNS, dns.String())
	}

	for _, addr := range c.cfg.Addresses {
		var isCurrent bool

		for _, newAddr := range newCfg.Addresses {
			if newAddr.Equal(addr) {
				isCurrent = true
				break
			}
		}

		if !isCurrent {
			for _, newAddr := range newCfg.OldAddresses {
				if newAddr.Equal(addr) {
					isCurrent = true
					break
				}
			}
		}

		if !isCurrent {
			newCfg.OldAddresses = append(newCfg.OldAddresses, addr)
		}
	}

	for _, prefix := range c.cfg.Prefixes {
		var isCurrent bool

		for _, newPrefix := range newCfg.Prefixes {
			if newPrefix.IP.Equal(prefix.IP) {
				isCurrent = true
				break
			}
		}

		if !isCurrent {
			for _, newPrefix := range newCfg.OldPrefixes {
				if newPrefix.IP.Equal(prefix.IP) {
					isCurrent = true
					break
				}
			}
		}

		if !isCurrent {
			newCfg.OldPrefixes = append(newCfg.OldPrefixes, prefix)
		}
	}

	c.cfg = newCfg
	return true
}

func (c *Client) Config() Config {
	return c.cfg
}
