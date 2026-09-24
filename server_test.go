package zeroconf

import (
	"testing"

	"github.com/miekg/dns"
)

// newTestEntries builds `len(instances)` proxy service entries all of the same _rpc._tcp
// type with a single IPv4 addr.
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

// browseQuery builds a browse question, a response message, and a query message with the
// question.
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

// countPTR counts PTRs (DNS pointer records) with the name `name` in `rrs`.
func countPTR(rrs []dns.RR, name string) int {
	n := 0
	for _, rr := range rrs {
		if ptr, ok := rr.(*dns.PTR); ok && ptr.Hdr.Name == name {
			n++
		}
	}
	return n
}

// TestAggregatedBrowseResponse asserts that a single browse of a service type with
// several registered instances yields one response.
func TestAggregatedBrowseResponse(t *testing.T) {
	s := newTestServer(t, "alpha", "alpha-dashed", "beta", "beta-dashed")

	q, resp, query := browseQuery("_rpc._tcp.local.")
	if err := s.handleQuestion(q, resp, query, 0); err != nil {
		t.Fatalf("handleQuestion: %v", err)
	}

	if got := countPTR(resp.Answer, "_rpc._tcp.local."); got != 4 {
		t.Fatalf("expected 4 browse PTRs, got %d (answers: %v)", got, resp.Answer)
	}

	// Each instance also has SRV, TXT and an A record in the Extra section (4 of each).
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
}

// TestServiceTypeEnumerationDedup asserts the _services._dns-sd._udp meta-query emits
// _one_ PTR even though several same-type entries are registered (see dedupe logic in
// `handleQuestion`).
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

// TestKnownAnswerSuppressionPerRecord asserts that one known answer suppresses only its
// own PTR.
func TestKnownAnswerSuppressionPerRecord(t *testing.T) {
	s := newTestServer(t, "alpha" /* known */, "beta", "gamma")

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

// TestInstanceLookupIsScoped asserts an instance lookup answers for that instance only
// and does not suppress the known answer.
func TestInstanceLookupIsScoped(t *testing.T) {
	s := newTestServer(t, "alpha" /* known */, "beta")

	// A known answer for the instance PTR must NOT suppress an instance lookup.
	known := &dns.PTR{
		Hdr: dns.RR_Header{Name: "_rpc._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 3200},
		Ptr: "alpha._rpc._tcp.local.",
	}
	q, resp, query := browseQuery("alpha._rpc._tcp.local.", known)
	if err := s.handleQuestion(q, resp, query, 0); err != nil {
		t.Fatalf("handleQuestion: %v", err)
	}

	// Answer must not be empty, and must not mention beta.
	if len(resp.Answer) == 0 {
		t.Fatal("instance lookup produced no answers")
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
