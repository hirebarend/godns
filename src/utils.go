package main

import "strings"

func buildFqdn(subDomain, parentDomain string) string {
	if subDomain == "" || subDomain == "@" {
		return parentDomain
	}

	if strings.HasSuffix(subDomain, ".") {
		return subDomain
	}

	return subDomain + "." + parentDomain
}

func orDefault(v, d uint32) uint32 {
	if v == 0 {
		return d
	}
	return v
}
