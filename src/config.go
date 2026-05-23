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

type config struct {
	Server struct {
		Addr string `yaml:"addr"`
	} `yaml:"server"`
	Zones []zone `yaml:"zones"`
}

type zone struct {
	Origin  string               `yaml:"origin"`
	TTL     uint32               `yaml:"ttl,omitempty"`
	Records map[string]recordSet `yaml:"records"`
}

type recordSet struct {
	TTL   uint32     `yaml:"ttl,omitempty"`
	SOA   *soaRecord `yaml:"soa,omitempty"`
	NS    []string   `yaml:"ns,omitempty"`
	A     []string   `yaml:"a,omitempty"`
	AAAA  []string   `yaml:"aaaa,omitempty"`
	CNAME string     `yaml:"cname,omitempty"`
	MX    []mxRecord `yaml:"mx,omitempty"`
	TXT   []string   `yaml:"txt,omitempty"`
}

type soaRecord struct {
	NS      string `yaml:"ns"`
	Mbox    string `yaml:"mbox"`
	Serial  uint32 `yaml:"serial"`
	Refresh uint32 `yaml:"refresh,omitempty"`
	Retry   uint32 `yaml:"retry,omitempty"`
	Expire  uint32 `yaml:"expire,omitempty"`
	MinTTL  uint32 `yaml:"min_ttl,omitempty"`
}

type mxRecord struct {
	Preference uint16 `yaml:"preference"`
	Host       string `yaml:"host"`
}

func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var c config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	return &c, nil
}

func (z zone) findNsRecords() []dns.RR {
	var out []dns.RR
	origin := z.origin()
	for _, rr := range z.recordsFor(origin) {
		if rr.Header().Rrtype == dns.TypeNS && strings.EqualFold(rr.Header().Name, origin) {
			out = append(out, rr)
		}
	}
	return out
}

func (z zone) findSoaRecord() dns.RR {
	origin := z.origin()
	for _, rr := range z.recordsFor(origin) {
		if rr.Header().Rrtype == dns.TypeSOA && strings.EqualFold(rr.Header().Name, origin) {
			return rr
		}
	}
	return nil
}

func (c *config) findZone(qname string) *zone {
	var best *zone
	for i := range c.Zones {
		z := &c.Zones[i]
		origin := z.origin()
		if strings.HasSuffix(qname, origin) && (best == nil || len(origin) > len(best.origin())) {
			best = z
		}
	}
	return best
}

func (z zone) origin() string {
	return dns.Fqdn(strings.ToLower(strings.TrimSpace(z.Origin)))
}

func (z zone) recordKey(qname string) string {
	qname = dns.Fqdn(strings.ToLower(strings.TrimSpace(qname)))
	origin := z.origin()
	if qname == origin {
		return "@"
	}

	return strings.TrimSuffix(qname, "."+origin)
}

func (z zone) recordSetFor(qname string) (recordSet, bool) {
	records, ok := z.Records[z.recordKey(qname)]
	return records, ok
}

func (z zone) recordsFor(qname string) []dns.RR {
	records, ok := z.recordSetFor(qname)
	if !ok {
		return nil
	}

	rrs, err := records.resourceRecords(z, z.recordKey(qname))
	if err != nil {
		return nil
	}

	return rrs
}

func (rs recordSet) resourceRecords(zone zone, name string) ([]dns.RR, error) {
	ttl := orDefault(rs.TTL, orDefault(zone.TTL, defaultTTL))
	owner := fqdn(name, zone.origin())
	header := dns.RR_Header{Name: owner, Class: dns.ClassINET, Ttl: ttl}

	var out []dns.RR
	if rs.SOA != nil {
		if owner != zone.origin() {
			return nil, fmt.Errorf("soa must be defined at @")
		}
		out = append(out, &dns.SOA{
			Hdr:     headerWithType(header, dns.TypeSOA),
			Ns:      dns.Fqdn(strings.ToLower(rs.SOA.NS)),
			Mbox:    dns.Fqdn(strings.ToLower(rs.SOA.Mbox)),
			Serial:  rs.SOA.Serial,
			Refresh: orDefault(rs.SOA.Refresh, defaultRefresh),
			Retry:   orDefault(rs.SOA.Retry, defaultRetry),
			Expire:  orDefault(rs.SOA.Expire, defaultExpire),
			Minttl:  orDefault(rs.SOA.MinTTL, defaultMinTTL),
		})
	}

	for _, ns := range rs.NS {
		out = append(out, &dns.NS{
			Hdr: headerWithType(header, dns.TypeNS),
			Ns:  dns.Fqdn(strings.ToLower(ns)),
		})
	}

	for _, value := range rs.A {
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("a value %q is not a valid IPv4 address", value)
		}
		out = append(out, &dns.A{
			Hdr: headerWithType(header, dns.TypeA),
			A:   ip.To4(),
		})
	}

	for _, value := range rs.AAAA {
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("aaaa value %q is not a valid IPv6 address", value)
		}
		out = append(out, &dns.AAAA{
			Hdr:  headerWithType(header, dns.TypeAAAA),
			AAAA: ip,
		})
	}

	if rs.CNAME != "" {
		out = append(out, &dns.CNAME{
			Hdr:    headerWithType(header, dns.TypeCNAME),
			Target: dns.Fqdn(strings.ToLower(rs.CNAME)),
		})
	}

	for _, mx := range rs.MX {
		out = append(out, &dns.MX{
			Hdr:        headerWithType(header, dns.TypeMX),
			Preference: mx.Preference,
			Mx:         dns.Fqdn(strings.ToLower(mx.Host)),
		})
	}

	for _, txt := range rs.TXT {
		out = append(out, &dns.TXT{
			Hdr: headerWithType(header, dns.TypeTXT),
			Txt: []string{txt},
		})
	}

	return out, nil
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

func headerWithType(header dns.RR_Header, recordType uint16) dns.RR_Header {
	header.Rrtype = recordType
	return header
}

func orDefault(v, d uint32) uint32 {
	if v == 0 {
		return d
	}
	return v
}
