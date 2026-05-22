package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/miekg/dns"
)

const defaultTTL = 300

type zoneData struct {
	origin string
	soa    *dns.SOA
}

var (
	zones   []*zoneData
	records []dns.RR
)

func matchZone(qname string) *zoneData {
	var best *zoneData
	for _, z := range zones {
		if strings.HasSuffix(qname, z.origin) && (best == nil || len(z.origin) > len(best.origin)) {
			best = z
		}
	}
	return best
}

func nameExists(qname string) bool {
	for _, rr := range records {
		if strings.EqualFold(rr.Header().Name, qname) {
			return true
		}
	}
	return false
}

func findAnswers(qname string, qtype uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range records {
		if !strings.EqualFold(rr.Header().Name, qname) {
			continue
		}
		if qtype == dns.TypeANY || rr.Header().Rrtype == qtype {
			out = append(out, rr)
		}
	}
	return out
}

func nsRRsFor(origin string) []dns.RR {
	var out []dns.RR
	for _, rr := range records {
		if rr.Header().Rrtype == dns.TypeNS && strings.EqualFold(rr.Header().Name, origin) {
			out = append(out, rr)
		}
	}
	return out
}

func handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true

	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	qname := strings.ToLower(q.Name)

	z := matchZone(qname)
	if z == nil {
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}

	m.Authoritative = true

	answers := findAnswers(qname, q.Qtype)
	switch {
	case len(answers) > 0:
		m.Answer = answers
		m.Ns = nsRRsFor(z.origin)
	case nameExists(qname):
		m.Ns = []dns.RR{z.soa}
	default:
		m.SetRcode(r, dns.RcodeNameError)
		m.Ns = []dns.RR{z.soa}
	}

	if err := w.WriteMsg(m); err != nil {
		log.Printf("write: %v", err)
	}
}

func zoneOrigins() []string {
	out := make([]string, len(zones))
	for i, z := range zones {
		out[i] = z.origin
	}
	return out
}

func main() {
	configPath := flag.String("config", "godns.yaml", "path to operator config YAML")
	zonesPath := flag.String("zones", "zones.yaml", "path to community zones YAML")
	addrOverride := flag.String("addr", "", "listen address (overrides server.addr from config)")
	flag.Parse()

	opCfg, err := loadOperatorConfig(*configPath)
	if err != nil {
		log.Fatalf("operator config: %v", err)
	}
	pubCfg, err := loadPublicConfig(*zonesPath)
	if err != nil {
		log.Fatalf("public config: %v", err)
	}

	opZone, opRRs, err := opCfg.build()
	if err != nil {
		log.Fatalf("operator zone: %v", err)
	}
	pubZones, pubRRs, err := pubCfg.build(opZone.origin, opCfg.Zone.PrimaryNS, opCfg.Zone.Nameservers, opCfg.Zone.Serial)
	if err != nil {
		log.Fatalf("public zones: %v", err)
	}

	zones = append([]*zoneData{opZone}, pubZones...)
	records = append(opRRs, pubRRs...)

	addr := *addrOverride
	if addr == "" {
		addr = opCfg.Server.Addr
	}
	if addr == "" {
		log.Fatalf("listen address not set (server.addr in %s or -addr flag)", *configPath)
	}

	dns.HandleFunc(".", handle)

	udp := &dns.Server{Addr: addr, Net: "udp"}
	tcp := &dns.Server{Addr: addr, Net: "tcp"}

	go func() {
		log.Printf("godns listening udp %s zones=%v", addr, zoneOrigins())
		if err := udp.ListenAndServe(); err != nil {
			log.Fatalf("udp: %v", err)
		}
	}()
	go func() {
		log.Printf("godns listening tcp %s zones=%v", addr, zoneOrigins())
		if err := tcp.ListenAndServe(); err != nil {
			log.Fatalf("tcp: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
	_ = udp.Shutdown()
	_ = tcp.Shutdown()
}
