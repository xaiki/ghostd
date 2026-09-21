package resolver

import (
	"context"
	"errors"
	"fmt"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalAnswersAndForwarding(t *testing.T) {
	for _, tc := range []struct {
		name    string
		typ     uint16
		count   int
		forward bool
	}{
		{"box.local.", dns.TypeA, 1, false}, {"BOX.LOCAL.", dns.TypeAAAA, 1, false},
		{"box.mesh.ts.net.", dns.TypeA, 0, true}, {"example.com.", dns.TypeA, 0, true},
	} {
		t.Run(tc.name+dns.TypeToString[tc.typ], func(t *testing.T) {
			forwarded := false
			h := &localHandler{slots: make(chan struct{}, 1), lookup: func(ctx context.Context, name string) ([]net.IP, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("missing lookup deadline")
				}
				return []net.IP{net.ParseIP("10.0.0.6"), net.ParseIP("fd00::6")}, nil
			}, next: plugin.HandlerFunc(func(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) { forwarded = true; return 0, nil })}
			r := new(dns.Msg)
			r.SetQuestion(tc.name, tc.typ)
			w := dnstest.NewRecorder(&test.ResponseWriter{})
			code, err := h.ServeDNS(context.Background(), w, r)
			if err != nil || code != 0 {
				t.Fatalf("%d %v", code, err)
			}
			if forwarded != tc.forward {
				t.Fatalf("forwarded=%v", forwarded)
			}
			if !tc.forward && len(w.Msg.Answer) != tc.count {
				t.Fatalf("%v", w.Msg)
			}
		})
	}
}
func TestLocalFailuresAreNotForwarded(t *testing.T) {
	for _, fail := range []bool{false, true} {
		h := &localHandler{slots: make(chan struct{}, 1), lookup: func(context.Context, string) ([]net.IP, error) {
			if fail {
				return nil, errors.New("timeout")
			}
			return nil, nil
		}}
		r := new(dns.Msg)
		r.SetQuestion("missing.local.", dns.TypeA)
		w := dnstest.NewRecorder(&test.ResponseWriter{})
		code, err := h.ServeDNS(context.Background(), w, r)
		if fail {
			if code != dns.RcodeServerFailure || err == nil {
				t.Fatal(code, err)
			}
		} else if w.Msg.Rcode != dns.RcodeNameError {
			t.Fatal(w.Msg)
		}
	}
}
func TestPublishReplacesRuntimeFile(t *testing.T) {
	dir := t.TempDir()
	for _, content := range []string{"old", "new"} {
		if err := publish(dir, "dns.env", content); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "dns.env"))
	if err != nil || string(data) != "new" {
		t.Fatal(string(data), err)
	}
	info, _ := os.Stat(filepath.Join(dir, "dns.env"))
	if info.Mode().Perm() != 0644 {
		t.Fatal(info.Mode())
	}
}

func TestEmbeddedServerForwardsTCPAndUDP(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		answer := new(dns.Msg)
		answer.SetReply(r)
		answer.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("100.64.0.2")}}
		_ = w.WriteMsg(answer)
	})}
	go upstream.ActivateAndServe()
	defer upstream.Shutdown()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	directory := t.TempDir()
	stop, err := start("127.0.0.1", port, packet.LocalAddr().String(), directory)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	for _, network := range []string{"udp", "tcp"} {
		client := &dns.Client{Net: network}
		query := new(dns.Msg)
		query.SetQuestion("worker.mesh.test.", dns.TypeA)
		reply, _, err := client.Exchange(query, net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
		if err != nil {
			t.Fatal(err)
		}
		if len(reply.Answer) != 1 || reply.Answer[0].(*dns.A).A.String() != "100.64.0.2" {
			t.Fatal(reply)
		}
	}
	env, err := os.ReadFile(filepath.Join(directory, "dns.env"))
	if err != nil || string(env) != "GHOSTD_DNS_ADDRESS=127.0.0.1\n" {
		t.Fatal(string(env), err)
	}
}
