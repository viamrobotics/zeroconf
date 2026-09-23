package zeroconf

import (
	"testing"

	"github.com/miekg/dns"
)

// newTestEntries builds n proxy service entries all of the same _rpc._tcp type (mirroring
// goutils' registration: several instance names on one responder) with a single IPv4 addr so
// appendAddrs does not need an interface lookup.
func newTestEntries(t *testing.T, instances ...string) []*ServiceEntry {
	t.Helper()
	entries := make([]*ServiceEntry, 0, len(instances))
	for _, inst := range instances {
		entry, err := NewProxyServiceEntry(inst, "_rpc._tcp", "local.", 8080, inst, []string{"127.0.0.1"}, []string{"key=val"})
		if err != nil {
			t.Fatalf("NewProxyServiceEntry(%q): %v", inst, err)
		}
		entries = append(entries, entry)
	}
	return entries
}

func newTestServer(t *testing.T, instances ...string) *Server {
	t.Helper()
	return &Server{services: newTestEntries(t, instances...), ttl: 3200}
}

// browseQuery builds a browse question and the reply skeleton handleQuestion expects, with
// the given known answers attached to the query (for known-answer suppression).
func browseQuery(name string, known ...dns.RR) (dns.Question, *dns.Msg, *dns.Msg) {
	query := new(dns.Msg)
	query.Answer = known
	q := dns.Question{Name: name, Qtype: dns.TypePTR, Qclass: dns.ClassINET}
	query.Question = []dns.Question{q}

	resp := new(dns.Msg)
	resp.Compress = true
	resp.Answer = []dns.RR{}
	resp.Extra = []dns.RR{}
	return q, resp, query
}

func countPTR(rrs []dns.RR, name string) int {
	n := 0
	for _, rr := range rrs {
		if ptr, ok := rr.(*dns.PTR); ok && ptr.Hdr.Name == name {
			n++
		}
	}
	return n
}

// TestAggregatedBrowseResponse asserts that a single browse of a service type with several
// registered instances yields one response carrying every instance's PTR, and that the whole
// thing packs into a single UDP datagram.
func TestAggregatedBrowseResponse(t *testing.T) {
	s := newTestServer(t, "alpha", "alpha-dashed", "beta", "beta-dashed")

	q, resp, query := browseQuery("_rpc._tcp.local.")
	if err := s.handleQuestion(q, resp, query, 0); err != nil {
		t.Fatalf("handleQuestion: %v", err)
	}

	if got := countPTR(resp.Answer, "_rpc._tcp.local."); got != 4 {
		t.Fatalf("expected 4 browse PTRs, got %d (answers: %v)", got, resp.Answer)
	}

	// Each instance also contributes SRV, TXT and an A record in the Extra section.
	var srv, txt, a int
	for _, rr := range resp.Extra {
		switch rr.(type) {
		case *dns.SRV:
			srv++
		case *dns.TXT:
			txt++
		case *dns.A:
			a++
		}
	}
	if srv != 4 || txt != 4 || a != 4 {
		t.Fatalf("expected 4 SRV/TXT/A each, got srv=%d txt=%d a=%d", srv, txt, a)
	}

	// Assert the aggregated response is a single datagram. RFC 6762 section 17 caps a
	// multicast DNS message at the interface MTU less headers; 1400 bytes stays under a
	// 1500-byte Ethernet MTU. With compression this response measures far less.
	packed, err := resp.Pack()
	if err != nil {
		t.Fatalf("packing aggregated response: %v", err)
	}
	if len(packed) >= 1400 {
		t.Fatalf("aggregated response too large for one datagram: %d bytes", len(packed))
	}
	t.Logf("aggregated browse response packed to %d bytes", len(packed))
}

// TestServiceTypeEnumerationDedup asserts the _services._dns-sd._udp meta-query emits one PTR
// even though several same-type entries are registered.
func TestServiceTypeEnumerationDedup(t *testing.T) {
	s := newTestServer(t, "alpha", "alpha-dashed", "beta", "beta-dashed")

	q, resp, query := browseQuery("_services._dns-sd._udp.local.")
	if err := s.handleQuestion(q, resp, query, 0); err != nil {
		t.Fatalf("handleQuestion: %v", err)
	}

	if got := countPTR(resp.Answer, "_services._dns-sd._udp.local."); got != 1 {
		t.Fatalf("expected 1 deduped service-type PTR, got %d", got)
	}
}

// TestKnownAnswerSuppressionPerRecord asserts that one known answer suppresses only its own
// PTR, not the whole aggregated set.
func TestKnownAnswerSuppressionPerRecord(t *testing.T) {
	s := newTestServer(t, "alpha", "beta", "gamma")

	known := &dns.PTR{
		Hdr: dns.RR_Header{Name: "_rpc._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 3200},
		Ptr: "alpha._rpc._tcp.local.",
	}
	q, resp, query := browseQuery("_rpc._tcp.local.", known)
	if err := s.handleQuestion(q, resp, query, 0); err != nil {
		t.Fatalf("handleQuestion: %v", err)
	}

	if got := countPTR(resp.Answer, "_rpc._tcp.local."); got != 2 {
		t.Fatalf("expected 2 PTRs after suppressing 1 known answer, got %d", got)
	}
	for _, rr := range resp.Answer {
		if ptr, ok := rr.(*dns.PTR); ok && ptr.Ptr == "alpha._rpc._tcp.local." {
			t.Fatalf("known answer alpha was not suppressed")
		}
	}
}

// TestInstanceLookupIsScoped asserts an instance lookup answers for that instance only and is
// not subject to known-answer suppression.
func TestInstanceLookupIsScoped(t *testing.T) {
	s := newTestServer(t, "alpha", "beta")

	// A known answer for the instance PTR must NOT suppress an instance lookup.
	known := &dns.PTR{
		Hdr: dns.RR_Header{Name: "_rpc._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 3200},
		Ptr: "alpha._rpc._tcp.local.",
	}
	q, resp, query := browseQuery("alpha._rpc._tcp.local.", known)
	if err := s.handleQuestion(q, resp, query, 0); err != nil {
		t.Fatalf("handleQuestion: %v", err)
	}

	// The lookup answer set (SRV, TXT, PTR, dnssd PTR, A) must be present, and must not
	// mention beta.
	if len(resp.Answer) == 0 {
		t.Fatal("instance lookup produced no answers (known-answer suppression leaked in?)")
	}
	for _, rr := range resp.Answer {
		if rr.Header().Name == "beta._rpc._tcp.local." {
			t.Fatalf("instance lookup for alpha leaked beta records")
		}
	}
}

func TestRegisterMultiRejectsEmpty(t *testing.T) {
	if _, err := RegisterMulti(nil, nil, nil); err == nil {
		t.Fatal("expected error for empty entries")
	}
}
