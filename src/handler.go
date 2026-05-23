package main

import (
	"strings"

	"github.com/miekg/dns"
)

func handler(config *dnsConfig, responseWriter dns.ResponseWriter, requestMsg *dns.Msg) {
	responseMsg := new(dns.Msg)
	responseMsg.SetReply(requestMsg)
	responseMsg.Compress = true

	if len(requestMsg.Question) == 0 {
		responseMsg.SetRcode(requestMsg, dns.RcodeFormatError)
		_ = responseWriter.WriteMsg(responseMsg)

		return
	}

	question := requestMsg.Question[0]

	qname := dns.Fqdn(strings.ToLower(question.Name))

	zone := config.matchZone(qname)
	if zone == nil {
		responseMsg.SetRcode(requestMsg, dns.RcodeRefused)
		responseMsg.Authoritative = false
		responseMsg.Answer = []dns.RR{}
		responseMsg.Ns = []dns.RR{}

		_ = responseWriter.WriteMsg(responseMsg)

		return
	}

	answers := config.findAnswers(qname, question.Qtype)

	if len(answers) > 0 {
		responseMsg.SetRcode(requestMsg, dns.RcodeSuccess)
		responseMsg.Authoritative = true
		responseMsg.Answer = answers
		responseMsg.Ns = config.nsRecordsFor(zone.origin)

		_ = responseWriter.WriteMsg(responseMsg)

		return
	}

	if config.nameExists(qname) {
		responseMsg.SetRcode(requestMsg, dns.RcodeSuccess)
		responseMsg.Authoritative = true
		responseMsg.Answer = []dns.RR{zone.soa}
		responseMsg.Ns = config.nsRecordsFor(zone.origin)

		_ = responseWriter.WriteMsg(responseMsg)

		return
	}

	responseMsg.SetRcode(requestMsg, dns.RcodeNameError)
	responseMsg.Authoritative = true
	responseMsg.Answer = []dns.RR{zone.soa}
	responseMsg.Ns = []dns.RR{}

	_ = responseWriter.WriteMsg(responseMsg)
}

func (c *dnsConfig) matchZone(qname string) *zoneData {
	var best *zoneData
	for _, z := range c.zones {
		if strings.HasSuffix(qname, z.origin) && (best == nil || len(z.origin) > len(best.origin)) {
			best = z
		}
	}
	return best
}

func (c *dnsConfig) nameExists(qname string) bool {
	for _, rr := range c.records {
		if strings.EqualFold(rr.Header().Name, qname) {
			return true
		}
	}
	return false
}

func (c *dnsConfig) findAnswers(qname string, qtype uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range c.records {
		if !strings.EqualFold(rr.Header().Name, qname) {
			continue
		}
		if qtype == dns.TypeANY || rr.Header().Rrtype == qtype {
			out = append(out, rr)
		}
	}
	return out
}

func (c *dnsConfig) nsRecordsFor(origin string) []dns.RR {
	var out []dns.RR
	for _, rr := range c.records {
		if rr.Header().Rrtype == dns.TypeNS && strings.EqualFold(rr.Header().Name, origin) {
			out = append(out, rr)
		}
	}
	return out
}
