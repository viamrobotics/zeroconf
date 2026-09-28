package zeroconf

import (
	"testing"

	"github.com/edaniels/golog"
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

// TestAggregatedBrowseResponsePacketSize asserts the aggregated browse response for several
// registered instances packs into a single message within the mDNS size limit and within
// a "normal" network MTU. Entries use a realistic shape: FQDN-length instance/host names (a long
// name plus its dot-to-dash alias), an IPv4 + IPv6 address, and a couple of TXT records.
func TestAggregatedBrowseResponsePacketSize(t *testing.T) {
	names := []string{
		"a1b2c3d4-e5f6-7890-abcd-ef1234567890.svc.example.com",
		"a1b2c3d4-e5f6-7890-abcd-ef1234567890-svc-example-com",
		"node.cluster-42.region.internal.example.com",
		"node-cluster-42-region-internal-example-com",
		"0f9e8d7c-6b5a-4321-fedc-ba0987654321.svc.example.com",
		"0f9e8d7c-6b5a-4321-fedc-ba0987654321-svc-example-com",
	}
	entries := make([]*ServiceEntry, 0, len(names))
	for _, n := range names {
		e, err := NewProxyServiceEntry(n, "_rpc._tcp", "local.", 8080, n,
			[]string{"192.168.1.42", "fe80::1ce:c4ff:fe96:95a1"}, []string{"txtvers=1", "proto=demo"})
		if err != nil {
			t.Fatalf("NewProxyServiceEntry(%q): %v", n, err)
		}
		entries = append(entries, e)
	}
	s := &Server{services: entries, ttl: 3200}

	q, resp, query := browseQuery("_rpc._tcp.local.")
	if err := s.handleQuestion(q, resp, query, 0); err != nil {
		t.Fatalf("handleQuestion: %v", err)
	}

	packed, err := resp.Pack()
	if err != nil {
		t.Fatalf("aggregated response failed to pack: %v", err)
	}
	t.Logf("aggregated response for %d instances packed to %d bytes", len(names), len(packed))

	// RFC 6762 section 17: a Multicast DNS message carried over UDP must not exceed 9000 bytes.
	if len(packed) > 9000 {
		t.Fatalf("aggregated response is %d bytes, over the 9000-byte mDNS limit", len(packed))
	}
	if len(packed) > 1500 {
		t.Fatalf("aggregated response is %d bytes, over a normal 1500-byte network limit", len(packed))
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

// TestKnownAnswerSuppressionPrunesExtras asserts a suppressed instance's SRV/TXT records do not
// ride along in the Extra section, while the surviving instances' extras remain.
func TestKnownAnswerSuppressionPrunesExtras(t *testing.T) {
	s := newTestServer(t, "alpha" /* known */, "beta", "gamma")

	known := &dns.PTR{
		Hdr: dns.RR_Header{Name: "_rpc._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 3200},
		Ptr: "alpha._rpc._tcp.local.",
	}
	q, resp, query := browseQuery("_rpc._tcp.local.", known)
	if err := s.handleQuestion(q, resp, query, 0); err != nil {
		t.Fatalf("handleQuestion: %v", err)
	}

	for _, rr := range resp.Extra {
		if rr.Header().Name == "alpha._rpc._tcp.local." {
			t.Fatalf("suppressed instance alpha leaked an SRV/TXT record: %v", rr)
		}
	}
	extras := map[string]int{}
	for _, rr := range resp.Extra {
		extras[rr.Header().Name]++
	}
	for _, inst := range []string{"beta", "gamma"} {
		if got := extras[inst+"._rpc._tcp.local."]; got != 2 { // SRV + TXT
			t.Fatalf("expected SRV+TXT for %s, got %d", inst, got)
		}
		if got := extras[inst+".local."]; got != 1 { // A
			t.Fatalf("expected 1 A record for %s, got %d", inst, got)
		}
	}
}

// TestRegisterMultiGuards asserts RegisterMulti rejects empty, oversized, and nil-containing entry
// slices rather than registering them.
func TestRegisterMultiGuards(t *testing.T) {
	logger := golog.NewTestLogger(t)

	if _, err := RegisterMulti(nil, nil, logger); err == nil {
		t.Fatal("expected error for no entries")
	}

	tooMany := newTestEntries(t, "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k")
	if _, err := RegisterMulti(tooMany, nil, logger); err == nil {
		t.Fatalf("expected error for %d entries (over the limit of %d)", len(tooMany), maxRegisterMultiEntries)
	}

	withNil := append(newTestEntries(t, "a"), nil)
	if _, err := RegisterMulti(withNil, nil, logger); err == nil {
		t.Fatal("expected error for a nil entry")
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
