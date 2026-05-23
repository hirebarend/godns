package main

import (
	"strings"

	"github.com/miekg/dns"
)

func handler(cfg *config, responseWriter dns.ResponseWriter, requestMsg *dns.Msg) {
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

	zone := cfg.findZone(qname)

	if zone == nil {
		responseMsg.SetRcode(requestMsg, dns.RcodeRefused)
		responseMsg.Authoritative = false
		responseMsg.Answer = []dns.RR{}
		responseMsg.Ns = []dns.RR{}

		_ = responseWriter.WriteMsg(responseMsg)

		return
	}

	answers := zone.findAnswers(qname, question.Qtype)

	if len(answers) > 0 {
		responseMsg.SetRcode(requestMsg, dns.RcodeSuccess)
		responseMsg.Authoritative = true
		responseMsg.Answer = answers
		responseMsg.Ns = zone.findNsRecords()

		_ = responseWriter.WriteMsg(responseMsg)

		return
	}

	if zone.nameExists(qname) {
		responseMsg.SetRcode(requestMsg, dns.RcodeSuccess)
		responseMsg.Authoritative = true
		responseMsg.Answer = []dns.RR{zone.findSoaRecord()}
		responseMsg.Ns = zone.findNsRecords()

		_ = responseWriter.WriteMsg(responseMsg)

		return
	}

	responseMsg.SetRcode(requestMsg, dns.RcodeNameError)
	responseMsg.Authoritative = true
	responseMsg.Answer = []dns.RR{zone.findSoaRecord()}
	responseMsg.Ns = []dns.RR{}

	_ = responseWriter.WriteMsg(responseMsg)
}

func (z zone) nameExists(qname string) bool {
	_, ok := z.recordSetFor(qname)
	return ok
}

func (z zone) findAnswers(qname string, qtype uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range z.recordsFor(qname) {
		if qtype == dns.TypeANY || rr.Header().Rrtype == qtype {
			out = append(out, rr)
		}
	}
	return out
}
