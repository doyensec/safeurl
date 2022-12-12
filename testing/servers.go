package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

/* dns */

var records4 = map[string]string{
	"service.test.": "127.0.0.1",
	"example.com.":  "93.184.216.34",
}

var records6 = map[string]string{
	"service6.test.": "::1",
	"example6.com.":  "2606:2800:220:1:248:1893:25c8:1946",
}

var rebind = make(map[string]int)

func doRebind(name string) (string, bool) {
	parts := strings.Split(strings.Split(name, ".")[0], "-")
	cleanName := strings.Replace(name, "-rbnd", "", 1)
	if len(parts) != 2 {
		return cleanName, false
	}

	name0 := parts[0]

	if parts[1] == "rbnd" {
		count, ok := rebind[name0]
		if !ok {
			count = 0
		} else {
			count++
		}

		rebind[name0] = count
		if count%2 == 0 {
			return cleanName, false
		} else {
			return cleanName, true
		}
	}

	return cleanName, false
}

func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeAAAA:
			log.Printf("AAAA query for %s\n", q.Name)

			name, rebind := doRebind(q.Name)
			ip := records6[name]

			if ip != "" {
				if rebind {
					ip = "::1"
				}
				rr, err := dns.NewRR(fmt.Sprintf("%s 0 AAAA %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}

		case dns.TypeA:
			log.Printf("A query for %s\n", q.Name)

			name, rebind := doRebind(q.Name)
			ip := records4[name]

			if ip != "" {
				if rebind {
					ip = "127.0.0.1"
				}
				rr, err := dns.NewRR(fmt.Sprintf("%s 0 A %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}

	w.WriteMsg(m)
}

func starDNSServer() {
	dns.HandleFunc("test.", handleDNSRequest)
	dns.HandleFunc("com.", handleDNSRequest)

	port := 8053
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	fmt.Printf("test dns server started. listening on: %v\n", port)

	err := server.ListenAndServe()
	defer server.Shutdown()

	if err != nil {
		log.Fatalf("failed to start server: %s\n ", err.Error())
	}
}

/* http */

func startHTTPServer() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("serving request: %v\n", r.URL.Path)
		fmt.Fprint(w, "ok")
	})

	const port = 8080

	fmt.Printf("test http server started. listening on: %v\n", port)
	http.ListenAndServe(fmt.Sprintf(":%v", port), nil)
}

func main() {
	wg := new(sync.WaitGroup)
	wg.Add(2)

	go func() {
		starDNSServer()
		wg.Done()
	}()

	go func() {
		startHTTPServer()
		wg.Done()
	}()

	wg.Wait()
}
