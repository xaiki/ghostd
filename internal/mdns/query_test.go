//go:build mdns

package mdns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A unicast stand-in for a LAN responder: it answers the way a legacy-unicast
// capable mDNS responder does, straight back to the asking port.
func responder(t *testing.T, records func(q dns.Question) []dns.RR) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := new(dns.Msg)
			if q.Unpack(buf[:n]) != nil || len(q.Question) != 1 {
				continue
			}
			r := new(dns.Msg)
			r.SetReply(q)
			r.Authoritative = true
			rrs := records(q.Question[0])
			for _, rr := range rrs {
				if rr.Header().Rrtype == q.Question[0].Qtype {
					r.Answer = append(r.Answer, rr)
				} else {
					r.Extra = append(r.Extra, rr)
				}
			}
			out, _ := r.Pack()
			pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

func TestBrowseCollectsInstanceRecords(t *testing.T) {
	hdr := func(name string, typ uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: typ, Class: dns.ClassINET | 0x8000, Ttl: 120}
	}
	addr := responder(t, func(q dns.Question) []dns.RR {
		if q.Name != "_ipp._tcp.local." {
			return nil
		}
		return []dns.RR{
			&dns.PTR{Hdr: hdr("_ipp._tcp.local.", dns.TypePTR), Ptr: "Office._ipp._tcp.local."},
			&dns.SRV{Hdr: hdr("Office._ipp._tcp.local.", dns.TypeSRV), Port: 631, Target: "printer.local."},
			&dns.TXT{Hdr: hdr("Office._ipp._tcp.local.", dns.TypeTXT), Txt: []string{"rp=ipp/print"}},
			&dns.A{Hdr: hdr("printer.local.", dns.TypeA), A: net.ParseIP("192.0.2.50")},
		}
	})
	q := &Querier{targets: []*net.UDPAddr{addr}, Window: 300 * time.Millisecond}
	rrs, err := q.Query(context.Background(), "_ipp._tcp.local.", dns.TypePTR)
	if err != nil {
		t.Fatal(err)
	}
	answers := Answers(rrs, "_ipp._tcp.local.", dns.TypePTR)
	if len(answers) != 1 {
		t.Fatal(rrs)
	}
	extra := Related(rrs, answers)
	if len(extra) != 2 { // SRV + TXT for the instance
		t.Fatal("instance records missing:", extra)
	}
	// Cache-flush bit stripped, TTL clamped.
	if answers[0].Header().Class != dns.ClassINET || answers[0].Header().Ttl != 30 {
		t.Fatal(answers[0].Header())
	}
}

func TestSilenceIsNotAnError(t *testing.T) {
	addr := responder(t, func(dns.Question) []dns.RR { return nil })
	q := &Querier{targets: []*net.UDPAddr{addr}, Window: 200 * time.Millisecond}
	rrs, err := q.Query(context.Background(), "nothing.local.", dns.TypeA)
	if err != nil || len(Answers(rrs, "nothing.local.", dns.TypeA)) != 0 {
		t.Fatal(rrs, err)
	}
}

func TestQueryHonoursContextDeadline(t *testing.T) {
	addr := responder(t, func(dns.Question) []dns.RR { return nil })
	q := &Querier{targets: []*net.UDPAddr{addr}, Window: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	q.Query(ctx, "x.local.", dns.TypeA)
	if time.Since(start) > 2*time.Second {
		t.Fatal("ignored the caller's deadline")
	}
}
