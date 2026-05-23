package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/miekg/dns"
)

func main() {
	configPath := flag.String("config", "godns.yaml", "path to config YAML")
	addrOverride := flag.String("addr", "", "listen address (overrides server.addr from config)")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	addr := *addrOverride
	if addr == "" {
		addr = cfg.addr
	}
	if addr == "" {
		log.Fatalf("listen address not set (server.addr in %s or -addr flag)", *configPath)
	}

	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		handler(cfg, w, r)
	})

	udp := &dns.Server{Addr: addr, Net: "udp"}
	tcp := &dns.Server{Addr: addr, Net: "tcp"}

	go func() {
		log.Printf("godns listening udp %s zones=%v", addr, cfg.zoneOrigins())
		if err := udp.ListenAndServe(); err != nil {
			log.Fatalf("udp: %v", err)
		}
	}()
	go func() {
		log.Printf("godns listening tcp %s zones=%v", addr, cfg.zoneOrigins())
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
