package nat64ptr

import (
	"context"
	"encoding/hex"
	"net"
	"strconv"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

const pluginName = "nat64ptr"

// NAT64PTR rewrites PTR requests for a configured NAT64 /96 IPv6 reverse zone
// into IPv4 in-addr.arpa. requests, then rewrites the response owner names back
// to the original IPv6 ip6.arpa. name expected by the client.
type NAT64PTR struct {
	Next          plugin.Handler
	prefix        net.IP
	reverseSuffix string
	backendSuffix string
	ptrSuffix     string
}

func (n *NAT64PTR) Name() string { return pluginName }

func (n *NAT64PTR) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if len(r.Question) == 0 {
		return plugin.NextOrFailure(n.Name(), n.Next, ctx, w, r)
	}

	question := r.Question[0]
	if question.Qtype != dns.TypePTR || !n.matchesReverseZone(question.Name) {
		return plugin.NextOrFailure(n.Name(), n.Next, ctx, w, r)
	}

	ipv4Name, ok := n.ipv4ReverseName(question.Name)
	if !ok {
		return plugin.NextOrFailure(n.Name(), n.Next, ctx, w, r)
	}

	originalName := question.Name
	r.Question[0].Name = ipv4Name

	rewriter := &responseRewriter{
		ResponseWriter: w,
		originalName:   originalName,
		ptrSuffix:      n.ptrSuffix,
	}

	return plugin.NextOrFailure(n.Name(), n.Next, ctx, rewriter, r)
}

func (n *NAT64PTR) matchesReverseZone(name string) bool {
	return dns.IsSubDomain(n.reverseSuffix, dns.Fqdn(name))
}

func newNAT64PTR(prefix *net.IPNet) *NAT64PTR {
	return &NAT64PTR{
		prefix:        prefix.IP.To16(),
		reverseSuffix: reverseSuffix(prefix.IP.To16(), 96),
		backendSuffix: "in-addr.arpa.",
	}
}

func (n *NAT64PTR) setBackendSuffix(suffix string) {
	n.backendSuffix = dns.Fqdn(suffix)
}

func (n *NAT64PTR) setPTRSuffix(suffix string) {
	n.ptrSuffix = dns.Fqdn(suffix)
}

func (n *NAT64PTR) ipv4ReverseName(name string) (string, bool) {
	labels := dns.SplitDomainName(name)
	if len(labels) < 8 {
		return "", false
	}

	bytes := make([]byte, 4)
	for i := range 4 {
		// ip6.arpa stores each byte as reversed nibbles, so decode high+low.
		lo := labels[i*2]
		hi := labels[i*2+1]
		if len(lo) != 1 || len(hi) != 1 {
			return "", false
		}

		decoded, err := hex.DecodeString(hi + lo)
		if err != nil || len(decoded) != 1 {
			return "", false
		}
		bytes[3-i] = decoded[0]
	}

	return dns.Fqdn(strings.Join([]string{
		byteString(bytes[3]),
		byteString(bytes[2]),
		byteString(bytes[1]),
		byteString(bytes[0]),
		strings.TrimSuffix(n.backendSuffix, "."),
	}, ".")), true
}

func byteString(value byte) string {
	return strconv.Itoa(int(value))
}

func reverseSuffix(ip net.IP, prefixBits int) string {
	nibbleCount := prefixBits / 4
	hexString := strings.ToLower(hex.EncodeToString(ip))
	labels := make([]string, 0, nibbleCount+2)

	for i := nibbleCount - 1; i >= 0; i-- {
		labels = append(labels, hexString[i:i+1])
	}

	labels = append(labels, "ip6", "arpa")
	return dns.Fqdn(strings.Join(labels, "."))
}

type responseRewriter struct {
	dns.ResponseWriter
	originalName string
	ptrSuffix    string
}

func (r *responseRewriter) WriteMsg(msg *dns.Msg) error {
	rewritten := msg.Copy()
	for i := range rewritten.Question {
		rewritten.Question[i].Name = r.originalName
	}

	hasPTR := false
	for _, answer := range rewritten.Answer {
		if _, ok := answer.(*dns.PTR); ok {
			hasPTR = true
		}
	}

	answers := rewritten.Answer[:0]
	for _, answer := range rewritten.Answer {
		if hasPTR && answer.Header().Rrtype == dns.TypeCNAME {
			continue
		}

		answer.Header().Name = r.originalName
		if ptr, ok := answer.(*dns.PTR); ok && r.ptrSuffix != "" {
			ptr.Ptr = dns.Fqdn(strings.TrimSuffix(ptr.Ptr, ".") + "." + strings.TrimSuffix(r.ptrSuffix, "."))
		}
		answers = append(answers, answer)
	}
	rewritten.Answer = answers

	return r.ResponseWriter.WriteMsg(rewritten)
}
