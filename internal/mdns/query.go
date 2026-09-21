// Package mdns is ghostd's query-side multicast DNS client. It sends legacy
// unicast queries (RFC 6762 section 6.7) from an ephemeral port, so it never
// binds UDP 5353 and never has to share it with another mDNS daemon: replies
// come straight back to the querying socket. This is what lets ghostd resolve
// and browse .local names on behalf of containers without avahi on the host.
package mdns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	group4 = &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	group6 = &net.UDPAddr{IP: net.ParseIP("ff02::fb"), Port: 5353}
)

// Querier asks the LAN. Interfaces names the LAN interfaces to query on; when
// empty, every up, multicast-capable, non-loopback interface is used.
type Querier struct {
	Interfaces []string
	// Window is how long answers are collected (default 700ms).
	Window time.Duration
	// targets overrides multicast destinations; tests point it at a unicast responder.
	targets []*net.UDPAddr
}

func (q *Querier) window() time.Duration {
	if q.Window > 0 {
		return q.Window
	}
	return 700 * time.Millisecond
}

func (q *Querier) interfaces() ([]net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []net.Interface
	for _, i := range all {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagMulticast == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(q.Interfaces) > 0 {
			listed := false
			for _, n := range q.Interfaces {
				listed = listed || n == i.Name
			}
			if !listed {
				continue
			}
		}
		out = append(out, i)
	}
	return out, nil
}

// Query multicasts one question and returns every record heard within the
// window whose owner name relates to the question (answers plus additionals),
// deduplicated. An empty result is a normal outcome, not an error.
func (q *Querier) Query(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = false
	wire, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	conn4, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	defer conn4.Close()
	var conn6 net.PacketConn
	if q.targets == nil {
		if c, e := net.ListenPacket("udp6", "[::]:0"); e == nil {
			conn6 = c
			defer c.Close()
		}
	}
	sent := 0
	if q.targets != nil {
		for _, t := range q.targets {
			if _, e := conn4.WriteTo(wire, t); e == nil {
				sent++
			}
		}
	} else {
		ifaces, e := q.interfaces()
		if e != nil {
			return nil, e
		}
		p4 := ipv4.NewPacketConn(conn4)
		p4.SetMulticastTTL(255)
		var p6 *ipv6.PacketConn
		if conn6 != nil {
			p6 = ipv6.NewPacketConn(conn6)
			p6.SetMulticastHopLimit(255)
		}
		for _, i := range ifaces {
			if e := p4.SetMulticastInterface(&i); e == nil {
				if _, e = p4.WriteTo(wire, &ipv4.ControlMessage{IfIndex: i.Index}, group4); e == nil {
					sent++
				}
			}
			if p6 != nil {
				if _, e := p6.WriteTo(wire, &ipv6.ControlMessage{IfIndex: i.Index}, group6); e == nil {
					sent++
				}
			}
		}
	}
	if sent == 0 {
		return nil, fmt.Errorf("mdns: no interface could send the query")
	}
	deadline := time.Now().Add(q.window())
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	type packet struct {
		data []byte
		err  error
	}
	results := make(chan packet, 64)
	read := func(c net.PacketConn) {
		if c == nil {
			return
		}
		c.SetReadDeadline(deadline)
		buf := make([]byte, 9000)
		for {
			n, _, e := c.ReadFrom(buf)
			if e != nil {
				return
			}
			results <- packet{data: append([]byte(nil), buf[:n]...)}
		}
	}
	done := make(chan struct{}, 2)
	go func() { read(conn4); done <- struct{}{} }()
	go func() { read(conn6); done <- struct{}{} }()
	var out []dns.RR
	seen := map[string]bool{}
	finished := 0
	for finished < 2 {
		select {
		case p := <-results:
			r := new(dns.Msg)
			if r.Unpack(p.data) != nil || !r.Response {
				continue
			}
			for _, rr := range append(append([]dns.RR{}, r.Answer...), r.Extra...) {
				if rr.Header().Rrtype == dns.TypeOPT || rr.Header().Rrtype == dns.TypeNSEC {
					continue
				}
				key := rr.String()
				if !seen[key] {
					seen[key] = true
					out = append(out, rr)
				}
			}
		case <-done:
			finished++
		case <-ctx.Done():
			return out, ctx.Err()
		}
	}
	for len(results) > 0 {
		p := <-results
		r := new(dns.Msg)
		if r.Unpack(p.data) == nil && r.Response {
			for _, rr := range append(append([]dns.RR{}, r.Answer...), r.Extra...) {
				if key := rr.String(); !seen[key] && rr.Header().Rrtype != dns.TypeOPT && rr.Header().Rrtype != dns.TypeNSEC {
					seen[key] = true
					out = append(out, rr)
				}
			}
		}
	}
	return out, nil
}

// Answers keeps the records that answer the question: the queried name and type
// (or a CNAME for it), with TTLs clamped to 30 seconds.
func Answers(rrs []dns.RR, name string, qtype uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		h := rr.Header()
		if !strings.EqualFold(h.Name, dns.Fqdn(name)) || (h.Rrtype != qtype && qtype != dns.TypeANY) {
			continue
		}
		c := dns.Copy(rr)
		c.Header().Class = dns.ClassINET // strip the cache-flush bit
		if c.Header().Ttl > 30 {
			c.Header().Ttl = 30
		}
		out = append(out, c)
	}
	return out
}

// Related returns additional records tied to the answers (SRV/TXT/A/AAAA for
// the targets a PTR or SRV names), so a browse answer is self-contained.
func Related(rrs []dns.RR, answers []dns.RR) []dns.RR {
	names := map[string]bool{}
	for _, a := range answers {
		switch v := a.(type) {
		case *dns.PTR:
			names[strings.ToLower(v.Ptr)] = true
		case *dns.SRV:
			names[strings.ToLower(v.Target)] = true
		}
	}
	var out []dns.RR
	for _, rr := range rrs {
		h := rr.Header()
		if !names[strings.ToLower(h.Name)] {
			continue
		}
		switch h.Rrtype {
		case dns.TypeSRV, dns.TypeTXT, dns.TypeA, dns.TypeAAAA:
			c := dns.Copy(rr)
			c.Header().Class = dns.ClassINET
			if c.Header().Ttl > 30 {
				c.Header().Ttl = 30
			}
			out = append(out, c)
		}
	}
	return out
}
