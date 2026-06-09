package nat64ptr

import (
	"context"
	"net"
	"testing"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

const exampleIPv6Name = "5.3.0.0.7.1.c.a.0.0.0.0.2.0.0.0.4.6.b.9.4.0.0.0.3.a.2.0.2.0.6.2.ip6.arpa."

func TestIPv4ReverseName(t *testing.T) {
	plugin := &NAT64PTR{backendSuffix: "in-addr.arpa."}
	got, ok := plugin.ipv4ReverseName(exampleIPv6Name)
	if !ok {
		t.Fatal("expected IPv4 reverse name")
	}

	want := "53.0.23.172.in-addr.arpa."
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestIPv4ReverseNameWithCustomBackendSuffix(t *testing.T) {
	plugin := &NAT64PTR{backendSuffix: "0.16.172.in-addr.arpa."}
	got, ok := plugin.ipv4ReverseName(exampleIPv6Name)
	if !ok {
		t.Fatal("expected IPv4 reverse name")
	}

	want := "53.0.23.172.0.16.172.in-addr.arpa."
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestServeDNSRewritesQuestionAndResponse(t *testing.T) {
	_, network, err := net.ParseCIDR("2602:2a3:4:9b64:2::/96")
	if err != nil {
		t.Fatal(err)
	}

	pluginUnderTest := newNAT64PTR(network)
	pluginUnderTest.Next = plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		if got, want := r.Question[0].Name, "53.0.23.172.in-addr.arpa."; got != want {
			t.Fatalf("rewritten question = %q, want %q", got, want)
		}

		response := new(dns.Msg)
		response.SetReply(r)
		response.Answer = []dns.RR{
			&dns.PTR{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60}, Ptr: "example.dn42."},
		}

		if err := w.WriteMsg(response); err != nil {
			t.Fatal(err)
		}

		return dns.RcodeSuccess, nil
	})

	request := new(dns.Msg)
	request.SetQuestion(exampleIPv6Name, dns.TypePTR)
	recorder := &responseRecorder{}

	if _, err := pluginUnderTest.ServeDNS(context.Background(), recorder, request); err != nil {
		t.Fatal(err)
	}

	if got := recorder.msg.Question[0].Name; got != exampleIPv6Name {
		t.Fatalf("response question = %q, want %q", got, exampleIPv6Name)
	}
	if got := recorder.msg.Answer[0].Header().Name; got != exampleIPv6Name {
		t.Fatalf("response answer = %q, want %q", got, exampleIPv6Name)
	}
}

type responseRecorder struct {
	msg *dns.Msg
}

func (r *responseRecorder) LocalAddr() net.Addr             { return &net.UDPAddr{} }
func (r *responseRecorder) RemoteAddr() net.Addr            { return &net.UDPAddr{} }
func (r *responseRecorder) WriteMsg(msg *dns.Msg) error     { r.msg = msg; return nil }
func (r *responseRecorder) Write(bytes []byte) (int, error) { return len(bytes), nil }
func (r *responseRecorder) Close() error                    { return nil }
func (r *responseRecorder) TsigStatus() error               { return nil }
func (r *responseRecorder) TsigTimersOnly(bool)             {}
func (r *responseRecorder) Hijack()                         {}
