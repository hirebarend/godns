package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/miekg/dns"
)

const (
	zone       = "godns.co.za."
	defaultTTL = 300
)

var records []dns.RR

func hdr(name string, rrtype uint16) dns.RR_Header {
	return dns.RR_Header{
		Name:   name,
		Rrtype: rrtype,
		Class:  dns.ClassINET,
		Ttl:    defaultTTL,
	}
}

func soa() *dns.SOA {
	return &dns.SOA{
		Hdr:     hdr(zone, dns.TypeSOA),
		Ns:      "ns1.godns.co.za.",
		Mbox:    "hostmaster.godns.co.za.",
		Serial:  2026052201,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  3600,
	}
}

func init() {
	records = []dns.RR{
		soa(),
		&dns.NS{Hdr: hdr(zone, dns.TypeNS), Ns: "ns1.godns.co.za."},
		&dns.NS{Hdr: hdr(zone, dns.TypeNS), Ns: "ns2.godns.co.za."},
		&dns.A{Hdr: hdr(zone, dns.TypeA), A: net.ParseIP("192.0.2.1")},
		&dns.AAAA{Hdr: hdr(zone, dns.TypeAAAA), AAAA: net.ParseIP("2001:db8::1")},
		&dns.MX{Hdr: hdr(zone, dns.TypeMX), Preference: 10, Mx: "mail.godns.co.za."},
		&dns.TXT{Hdr: hdr(zone, dns.TypeTXT), Txt: []string{"v=spf1 -all"}},
		&dns.A{Hdr: hdr("www.godns.co.za.", dns.TypeA), A: net.ParseIP("192.0.2.2")},
		&dns.A{Hdr: hdr("ns1.godns.co.za.", dns.TypeA), A: net.ParseIP("192.0.2.10")},
		&dns.A{Hdr: hdr("ns2.godns.co.za.", dns.TypeA), A: net.ParseIP("192.0.2.11")},
		&dns.A{Hdr: hdr("mail.godns.co.za.", dns.TypeA), A: net.ParseIP("192.0.2.20")},
	}
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

func nsRRs() []dns.RR {
	var out []dns.RR
	for _, rr := range records {
		if rr.Header().Rrtype == dns.TypeNS {
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

	if !strings.HasSuffix(qname, zone) {
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}

	m.Authoritative = true

	answers := findAnswers(qname, q.Qtype)
	switch {
	case len(answers) > 0:
		m.Answer = answers
		m.Ns = nsRRs()
	case nameExists(qname):
		m.Ns = []dns.RR{soa()}
	default:
		m.SetRcode(r, dns.RcodeNameError)
		m.Ns = []dns.RR{soa()}
	}

	if err := w.WriteMsg(m); err != nil {
		log.Printf("write: %v", err)
	}
}

func main() {
	addr := flag.String("addr", ":15353", "listen address (use :53 for privileged mode)")
	flag.Parse()

	dns.HandleFunc(zone, handle)
	dns.HandleFunc(".", handle)

	udp := &dns.Server{Addr: *addr, Net: "udp"}
	tcp := &dns.Server{Addr: *addr, Net: "tcp"}

	go func() {
		log.Printf("godns listening udp %s zone=%s", *addr, zone)
		if err := udp.ListenAndServe(); err != nil {
			log.Fatalf("udp: %v", err)
		}
	}()
	go func() {
		log.Printf("godns listening tcp %s zone=%s", *addr, zone)
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
