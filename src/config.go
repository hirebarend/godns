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

	var config config
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	return &config, nil
}

func (zone zone) findNsRecords() []dns.RR {
	recordSet, ok := zone.Records[zone.getRecordKey(zone.Origin)]

	if !ok {
		return nil
	}

	rrs, err := recordSet.toRRs(zone, "@")

	if err != nil {
		return nil
	}

	var out []dns.RR

	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeNS && strings.EqualFold(rr.Header().Name, zone.Origin) {
			out = append(out, rr)
		}
	}

	return out
}

func (zone zone) findSoaRecord() dns.RR {
	recordSet, ok := zone.Records[zone.getRecordKey(zone.Origin)]

	if !ok {
		return nil
	}

	rrs, err := recordSet.toRRs(zone, "@")

	if err != nil {
		return nil
	}

	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeSOA && strings.EqualFold(rr.Header().Name, zone.Origin) {
			return rr
		}
	}
	return nil
}

func (config *config) findZone(qname string) *zone {
	var best *zone

	for i := range config.Zones {
		zone := &config.Zones[i]

		if strings.HasSuffix(qname, zone.Origin) && (best == nil || len(zone.Origin) > len(best.Origin)) {
			best = zone
		}
	}

	return best
}

func (zone zone) getRecordKey(questionName string) string {
	if questionName == zone.Origin {
		return "@"
	}

	return strings.TrimSuffix(questionName, "."+zone.Origin)
}

func (recordSet recordSet) toRRs(zone zone, name string) ([]dns.RR, error) {
	ttl := orDefault(recordSet.TTL, orDefault(zone.TTL, defaultTTL))
	header := dns.RR_Header{Name: buildFqdn(name, zone.Origin), Class: dns.ClassINET, Ttl: ttl}

	var out []dns.RR
	if recordSet.SOA != nil {
		out = append(out, &dns.SOA{
			Hdr:     headerWithType(header, dns.TypeSOA),
			Ns:      dns.Fqdn(strings.ToLower(recordSet.SOA.NS)),
			Mbox:    dns.Fqdn(strings.ToLower(recordSet.SOA.Mbox)),
			Serial:  recordSet.SOA.Serial,
			Refresh: orDefault(recordSet.SOA.Refresh, defaultRefresh),
			Retry:   orDefault(recordSet.SOA.Retry, defaultRetry),
			Expire:  orDefault(recordSet.SOA.Expire, defaultExpire),
			Minttl:  orDefault(recordSet.SOA.MinTTL, defaultMinTTL),
		})
	}

	for _, ns := range recordSet.NS {
		out = append(out, &dns.NS{
			Hdr: headerWithType(header, dns.TypeNS),
			Ns:  dns.Fqdn(strings.ToLower(ns)),
		})
	}

	for _, value := range recordSet.A {
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("a value %q is not a valid IPv4 address", value)
		}
		out = append(out, &dns.A{
			Hdr: headerWithType(header, dns.TypeA),
			A:   ip.To4(),
		})
	}

	for _, value := range recordSet.AAAA {
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("aaaa value %q is not a valid IPv6 address", value)
		}
		out = append(out, &dns.AAAA{
			Hdr:  headerWithType(header, dns.TypeAAAA),
			AAAA: ip,
		})
	}

	if recordSet.CNAME != "" {
		out = append(out, &dns.CNAME{
			Hdr:    headerWithType(header, dns.TypeCNAME),
			Target: dns.Fqdn(strings.ToLower(recordSet.CNAME)),
		})
	}

	for _, mx := range recordSet.MX {
		out = append(out, &dns.MX{
			Hdr:        headerWithType(header, dns.TypeMX),
			Preference: mx.Preference,
			Mx:         dns.Fqdn(strings.ToLower(mx.Host)),
		})
	}

	for _, txt := range recordSet.TXT {
		out = append(out, &dns.TXT{
			Hdr: headerWithType(header, dns.TypeTXT),
			Txt: []string{txt},
		})
	}

	return out, nil
}

func headerWithType(header dns.RR_Header, recordType uint16) dns.RR_Header {
	header.Rrtype = recordType
	return header
}
