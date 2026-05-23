package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/miekg/dns"
)

func main() {
	cfg, err := loadConfig("config.yaml")

	if err != nil {
		log.Fatalf("config: %v", err)
	}

	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		handler(cfg, w, r)
	})

	udp := &dns.Server{Addr: cfg.Server.Addr, Net: "udp"}
	tcp := &dns.Server{Addr: cfg.Server.Addr, Net: "tcp"}

	go func() {
		log.Printf("godns listening udp %s", cfg.Server.Addr)
		if err := udp.ListenAndServe(); err != nil {
			log.Fatalf("udp: %v", err)
		}
	}()

	go func() {
		log.Printf("godns listening tcp %s", cfg.Server.Addr)
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
