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

type operatorZoneConfig struct {
	Origin      string         `yaml:"origin"`
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

type operatorConfig struct {
	Server serverConfig       `yaml:"server"`
	Zone   operatorZoneConfig `yaml:"zone"`
}

type publicZoneConfig struct {
	Domain  string         `yaml:"domain"`
	Owner   string         `yaml:"owner,omitempty"`
	TTL     uint32         `yaml:"ttl,omitempty"`
	Records []recordConfig `yaml:"records"`
}

type publicConfig struct {
	Zones []publicZoneConfig `yaml:"zones"`
}

func loadOperatorConfig(path string) (*operatorConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read operator config %s: %w", path, err)
	}
	var c operatorConfig
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

func loadPublicConfig(path string) (*publicConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &publicConfig{}, nil
		}
		return nil, fmt.Errorf("read public config %s: %w", path, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return &publicConfig{}, nil
	}
	var c publicConfig
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// fqdn returns name as a fully-qualified, lower-cased DNS name under zoneOrigin.
// "@" → zoneOrigin; bare label "www" → "www.<origin>"; trailing-dot value is kept.
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

func validDomain(s string) bool {
	if s == "" {
		return false
	}
	_, ok := dns.IsDomainName(s)
	return ok
}

// buildOperator turns operatorConfig into a *zoneData and its records.
func (oc *operatorConfig) build() (*zoneData, []dns.RR, error) {
	z := oc.Zone
	if !validDomain(z.Origin) {
		return nil, nil, fmt.Errorf("zone.origin %q is not a valid domain", z.Origin)
	}
	if !validDomain(z.PrimaryNS) {
		return nil, nil, fmt.Errorf("zone.primary_ns %q is not a valid domain", z.PrimaryNS)
	}
	if !validDomain(z.Hostmaster) {
		return nil, nil, fmt.Errorf("zone.hostmaster %q is not a valid domain", z.Hostmaster)
	}
	if z.Serial == 0 {
		return nil, nil, fmt.Errorf("zone.serial is required")
	}
	if len(z.Nameservers) == 0 {
		return nil, nil, fmt.Errorf("zone.nameservers must list at least one host")
	}
	for i, ns := range z.Nameservers {
		if !validDomain(ns) {
			return nil, nil, fmt.Errorf("zone.nameservers[%d] %q is not a valid domain", i, ns)
		}
	}

	origin := dns.Fqdn(strings.ToLower(z.Origin))
	ttl := z.TTL
	if ttl == 0 {
		ttl = defaultTTL
	}

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: origin, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      dns.Fqdn(strings.ToLower(z.PrimaryNS)),
		Mbox:    dns.Fqdn(strings.ToLower(z.Hostmaster)),
		Serial:  z.Serial,
		Refresh: orDefault(z.Refresh, defaultRefresh),
		Retry:   orDefault(z.Retry, defaultRetry),
		Expire:  orDefault(z.Expire, defaultExpire),
		Minttl:  orDefault(z.MinTTL, defaultMinTTL),
	}

	zd := &zoneData{origin: origin, soa: soa}
	rrs := []dns.RR{soa}

	for _, ns := range z.Nameservers {
		rrs = append(rrs, &dns.NS{
			Hdr: dns.RR_Header{Name: origin, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
			Ns:  dns.Fqdn(strings.ToLower(ns)),
		})
	}

	for i, rc := range z.Records {
		if strings.EqualFold(rc.Type, "NS") || strings.EqualFold(rc.Type, "SOA") {
			return nil, nil, fmt.Errorf("zone.records[%d]: %s is managed by the server, do not list it", i, strings.ToUpper(rc.Type))
		}
		rr, err := rc.toRR(origin, ttl)
		if err != nil {
			return nil, nil, fmt.Errorf("zone.records[%d]: %w", i, err)
		}
		rrs = append(rrs, rr)
	}

	return zd, rrs, nil
}

// buildPublic turns publicConfig into per-zone metadata and records. The operator
// determines the SOA primary NS and the NS list used for every contributed zone.
func (pc *publicConfig) build(operatorOrigin, primaryNS string, nameservers []string, soaSerial uint32) ([]*zoneData, []dns.RR, error) {
	operatorOrigin = dns.Fqdn(strings.ToLower(operatorOrigin))
	primaryNS = dns.Fqdn(strings.ToLower(primaryNS))

	zoneDatas := make([]*zoneData, 0, len(pc.Zones))
	var rrs []dns.RR
	seen := map[string]int{}

	for i, pz := range pc.Zones {
		if !validDomain(pz.Domain) {
			return nil, nil, fmt.Errorf("zones[%d].domain %q is not a valid domain", i, pz.Domain)
		}
		domain := dns.Fqdn(strings.ToLower(pz.Domain))

		if domain == operatorOrigin || strings.HasSuffix(domain, "."+operatorOrigin) {
			return nil, nil, fmt.Errorf("zones[%d]: %s is inside the operator zone %s and cannot be contributed", i, domain, operatorOrigin)
		}
		if prev, dup := seen[domain]; dup {
			return nil, nil, fmt.Errorf("zones[%d]: duplicate domain %s (first declared at zones[%d])", i, domain, prev)
		}
		seen[domain] = i

		ttl := pz.TTL
		if ttl == 0 {
			ttl = defaultTTL
		}

		soa := &dns.SOA{
			Hdr:     dns.RR_Header{Name: domain, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
			Ns:      primaryNS,
			Mbox:    dns.Fqdn("hostmaster." + strings.ToLower(pz.Domain)),
			Serial:  soaSerial,
			Refresh: defaultRefresh,
			Retry:   defaultRetry,
			Expire:  defaultExpire,
			Minttl:  defaultMinTTL,
		}

		zd := &zoneData{origin: domain, soa: soa}
		zoneDatas = append(zoneDatas, zd)

		rrs = append(rrs, soa)
		for _, ns := range nameservers {
			rrs = append(rrs, &dns.NS{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
				Ns:  dns.Fqdn(strings.ToLower(ns)),
			})
		}

		for j, rc := range pz.Records {
			if !isPublicRecordType(rc.Type) {
				return nil, nil, fmt.Errorf("zones[%d].records[%d]: type %q is not allowed (use A, AAAA, CNAME, MX, TXT)", i, j, rc.Type)
			}
			rr, err := rc.toRR(domain, ttl)
			if err != nil {
				return nil, nil, fmt.Errorf("zones[%d].records[%d]: %w", i, j, err)
			}
			rrs = append(rrs, rr)
		}
	}

	return zoneDatas, rrs, nil
}

func isPublicRecordType(t string) bool {
	switch strings.ToUpper(t) {
	case "A", "AAAA", "CNAME", "MX", "TXT":
		return true
	}
	return false
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
		if !validDomain(rc.Value) {
			return nil, fmt.Errorf("CNAME target %q is not a valid domain", rc.Value)
		}
		header.Rrtype = dns.TypeCNAME
		return &dns.CNAME{Hdr: header, Target: dns.Fqdn(strings.ToLower(rc.Value))}, nil

	case "MX":
		if rc.Priority == 0 {
			return nil, fmt.Errorf("MX requires priority > 0")
		}
		if !validDomain(rc.Value) {
			return nil, fmt.Errorf("MX target %q is not a valid domain", rc.Value)
		}
		header.Rrtype = dns.TypeMX
		return &dns.MX{Hdr: header, Preference: rc.Priority, Mx: dns.Fqdn(strings.ToLower(rc.Value))}, nil

	case "TXT":
		txt := rc.Values
		if len(txt) == 0 && rc.Value != "" {
			txt = []string{rc.Value}
		}
		if len(txt) == 0 {
			return nil, fmt.Errorf("TXT requires value or values")
		}
		header.Rrtype = dns.TypeTXT
		return &dns.TXT{Hdr: header, Txt: txt}, nil

	case "NS":
		if !validDomain(rc.Value) {
			return nil, fmt.Errorf("NS target %q is not a valid domain", rc.Value)
		}
		header.Rrtype = dns.TypeNS
		return &dns.NS{Hdr: header, Ns: dns.Fqdn(strings.ToLower(rc.Value))}, nil

	default:
		return nil, fmt.Errorf("unsupported record type %q", rc.Type)
	}
}
