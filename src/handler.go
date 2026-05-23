package main

import (
	"log"

	"github.com/miekg/dns"
)

func handler(config *config, responseWriter dns.ResponseWriter, requestMsg *dns.Msg) {
	responseMsg := new(dns.Msg)
	responseMsg.SetReply(requestMsg)
	responseMsg.Compress = true

	if len(requestMsg.Question) == 0 {
		responseMsg.SetRcode(requestMsg, dns.RcodeFormatError)
		_ = responseWriter.WriteMsg(responseMsg)

		return
	}

	for _, question := range requestMsg.Question {
		log.Printf(
			"query client=%s name=%s type=%s class=%s",
			responseWriter.RemoteAddr(),
			question.Name,
			dns.TypeToString[question.Qtype],
			dns.ClassToString[question.Qclass],
		)
	}

	question := requestMsg.Question[0]
	zone := config.findZone(question.Name)

	if zone == nil {
		responseMsg.SetRcode(requestMsg, dns.RcodeRefused)
		responseMsg.Authoritative = false
		responseMsg.Answer = []dns.RR{}
		responseMsg.Ns = []dns.RR{}

		_ = responseWriter.WriteMsg(responseMsg)

		return
	}

	recordSet, ok := zone.Records[zone.getRecordKey(question.Name)]

	rrs, _ := recordSet.toRRs(*zone, question.Name)

	var out []dns.RR
	for _, rr := range rrs {
		if question.Qtype == dns.TypeANY || rr.Header().Rrtype == question.Qtype {
			out = append(out, rr)
		}
	}

	if len(out) > 0 {
		responseMsg.SetRcode(requestMsg, dns.RcodeSuccess)
		responseMsg.Authoritative = true
		responseMsg.Answer = out
		responseMsg.Ns = zone.findNsRecords()

		_ = responseWriter.WriteMsg(responseMsg)

		return
	}

	if ok {
		responseMsg.SetRcode(requestMsg, dns.RcodeSuccess)
		responseMsg.Authoritative = true
		responseMsg.Answer = []dns.RR{}
		responseMsg.Ns = []dns.RR{zone.findSoaRecord()}

		_ = responseWriter.WriteMsg(responseMsg)

		return
	}

	responseMsg.SetRcode(requestMsg, dns.RcodeNameError)
	responseMsg.Authoritative = true
	responseMsg.Answer = []dns.RR{}
	responseMsg.Ns = []dns.RR{zone.findSoaRecord()}

	_ = responseWriter.WriteMsg(responseMsg)
}
