package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

const (
	defaultTTL     = uint32(300)
	defaultRefresh = uint32(7200)
	defaultRetry   = uint32(3600)
	defaultExpire  = uint32(1209600)
	defaultMinTTL  = uint32(3600)
)

type serverConfig struct {
	Addr string `yaml:"addr"`
}

type recordConfig struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Value    string   `yaml:"value,omitempty"`
	Values   []string `yaml:"values,omitempty"`
	Priority uint16   `yaml:"priority,omitempty"`
	TTL      uint32   `yaml:"ttl,omitempty"`
}

type zoneConfig struct {
	Domain      string         `yaml:"domain"`
	PrimaryNS   string         `yaml:"primary_ns"`
	Hostmaster  string         `yaml:"hostmaster"`
	Serial      uint32         `yaml:"serial"`
	Refresh     uint32         `yaml:"refresh,omitempty"`
	Retry       uint32         `yaml:"retry,omitempty"`
	Expire      uint32         `yaml:"expire,omitempty"`
	MinTTL      uint32         `yaml:"min_ttl,omitempty"`
	TTL         uint32         `yaml:"ttl,omitempty"`
	Nameservers []string       `yaml:"nameservers"`
	Records     []recordConfig `yaml:"records"`
}

type fileConfig struct {
	Server serverConfig `yaml:"server"`
	Zones  []zoneConfig `yaml:"zones"`
}

type zoneData struct {
	origin string
	soa    *dns.SOA
}

type dnsConfig struct {
	addr    string
	zones   []*zoneData
	records []dns.RR
}

func loadConfig(path string) (*dnsConfig, error) {
	data, err := os.ReadFile(path)

	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var c fileConfig

	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)

	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	zones, records, err := c.buildZones()

	if err != nil {
		return nil, err
	}

	return &dnsConfig{
		addr:    c.Server.Addr,
		zones:   zones,
		records: records,
	}, nil
}

func (c *dnsConfig) zoneOrigins() []string {
	out := make([]string, len(c.zones))

	for i, z := range c.zones {
		out[i] = z.origin
	}

	return out
}

func fqdn(name, zoneOrigin string) string {
	zoneOrigin = dns.Fqdn(strings.ToLower(zoneOrigin))

	name = strings.ToLower(strings.TrimSpace(name))

	if name == "" || name == "@" {
		return zoneOrigin
	}

	if strings.HasSuffix(name, ".") {
		return name
	}

	return name + "." + zoneOrigin
}

func (c *fileConfig) buildZones() ([]*zoneData, []dns.RR, error) {
	zoneDatas := make([]*zoneData, 0, len(c.Zones))

	var rrs []dns.RR

	for i, z := range c.Zones {
		domain := dns.Fqdn(strings.ToLower(z.Domain))
		ttl := z.TTL
		if ttl == 0 {
			ttl = defaultTTL
		}

		soa := &dns.SOA{
			Hdr:     dns.RR_Header{Name: domain, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
			Ns:      dns.Fqdn(strings.ToLower(z.PrimaryNS)),
			Mbox:    dns.Fqdn(strings.ToLower(z.Hostmaster)),
			Serial:  z.Serial,
			Refresh: orDefault(z.Refresh, defaultRefresh),
			Retry:   orDefault(z.Retry, defaultRetry),
			Expire:  orDefault(z.Expire, defaultExpire),
			Minttl:  orDefault(z.MinTTL, defaultMinTTL),
		}

		zd := &zoneData{origin: domain, soa: soa}
		zoneDatas = append(zoneDatas, zd)

		rrs = append(rrs, soa)
		for _, ns := range z.Nameservers {
			rrs = append(rrs, &dns.NS{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
				Ns:  dns.Fqdn(strings.ToLower(ns)),
			})
		}

		for j, rc := range z.Records {
			rr, err := rc.toRR(domain, ttl)
			if err != nil {
				return nil, nil, fmt.Errorf("zones[%d].records[%d]: %w", i, j, err)
			}
			rrs = append(rrs, rr)
		}
	}

	return zoneDatas, rrs, nil
}

func orDefault(v, d uint32) uint32 {
	if v == 0 {
		return d
	}

	return v
}

func (rc recordConfig) toRR(zoneOrigin string, zoneTTL uint32) (dns.RR, error) {
	name := fqdn(rc.Name, zoneOrigin)

	ttl := rc.TTL
	if ttl == 0 {
		ttl = zoneTTL
	}

	header := dns.RR_Header{Name: name, Class: dns.ClassINET, Ttl: ttl}

	switch strings.ToUpper(rc.Type) {
	case "A":
		ip := net.ParseIP(rc.Value)

		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("A value %q is not a valid IPv4 address", rc.Value)
		}

		header.Rrtype = dns.TypeA

		return &dns.A{Hdr: header, A: ip.To4()}, nil

	case "AAAA":
		ip := net.ParseIP(rc.Value)

		if ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("AAAA value %q is not a valid IPv6 address", rc.Value)
		}

		header.Rrtype = dns.TypeAAAA

		return &dns.AAAA{Hdr: header, AAAA: ip}, nil

	case "CNAME":
		header.Rrtype = dns.TypeCNAME
		return &dns.CNAME{Hdr: header, Target: dns.Fqdn(strings.ToLower(rc.Value))}, nil

	case "MX":
		header.Rrtype = dns.TypeMX
		return &dns.MX{Hdr: header, Preference: rc.Priority, Mx: dns.Fqdn(strings.ToLower(rc.Value))}, nil

	case "TXT":
		txt := rc.Values

		if len(txt) == 0 && rc.Value != "" {
			txt = []string{rc.Value}
		}

		header.Rrtype = dns.TypeTXT

		return &dns.TXT{Hdr: header, Txt: txt}, nil

	case "NS":
		header.Rrtype = dns.TypeNS

		return &dns.NS{Hdr: header, Ns: dns.Fqdn(strings.ToLower(rc.Value))}, nil

	default:
		return nil, fmt.Errorf("unsupported record type %q", rc.Type)
	}
}
