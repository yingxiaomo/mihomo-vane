package xhttp

import (
	"bytes"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
)

type testRoundTripper struct {
	id int64
}

func (t *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	panic("not used in reuse manager unit tests")
}

// failingRoundTripper stands in for a pooled connection that the edge already
// closed: every request on it fails at the transport layer.
type failingRoundTripper struct {
	id int64
}

func (t *failingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, errors.New("read tcp: connection reset by peer")
}

// healthyRoundTripper stands in for a pooled connection that still works.
type healthyRoundTripper struct {
	id int64
}

func (t *healthyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(nil))}, nil
}

func makeRoundTripperFactory(counter *atomic.Int64, fail bool) TransportMaker {
	return func() http.RoundTripper {
		id := counter.Add(1)
		if fail {
			return &failingRoundTripper{id: id}
		}
		return &healthyRoundTripper{id: id}
	}
}

func roundTripperID(rt *ReuseTransport) int64 {
	switch tr := rt.entry.transport.(type) {
	case *testRoundTripper:
		return tr.id
	case *failingRoundTripper:
		return tr.id
	case *healthyRoundTripper:
		return tr.id
	}
	panic("unexpected transport")
}

func makeTestTransportFactory(counter *atomic.Int64) TransportMaker {
	return func() http.RoundTripper {
		id := counter.Add(1)
		return &testRoundTripper{id: id}
	}
}

func transportID(rt *ReuseTransport) int64 {
	return rt.entry.transport.(*testRoundTripper).id
}

func TestManagerReuseSameEntry(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConcurrency:   "1",
		MaxConnections:   "1",
		HMaxRequestTimes: "10",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}

	transport1 := manager.GetTransport().(*ReuseTransport)
	id1 := transportID(transport1)

	transport1.Close()

	transport2 := manager.GetTransport().(*ReuseTransport)
	id2 := transportID(transport2)

	if id1 != id2 {
		t.Fatalf("expected same transport to be reused, got %d and %d", id1, id2)
	}

	transport2.Close()
	manager.Close()
}

func TestManagerRespectMaxConnections(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConcurrency:   "2",
		MaxConnections:   "2",
		HMaxRequestTimes: "100",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}

	transport1 := manager.GetTransport().(*ReuseTransport)
	id1 := transportID(transport1)
	transport2 := manager.GetTransport().(*ReuseTransport)
	id2 := transportID(transport2)
	transport3 := manager.GetTransport().(*ReuseTransport)
	id3 := transportID(transport3)
	transport4 := manager.GetTransport().(*ReuseTransport)
	id4 := transportID(transport4)
	transport5 := manager.GetTransport().(*ReuseTransport)
	id5 := transportID(transport5)

	if id1 == id2 {
		t.Fatal("expected the second transport to be new")
	}

	if id3 != id1 && id3 != id2 {
		t.Fatal("expected the third transport to be reused")
	}

	if id4 != id1 && id4 != id2 {
		t.Fatal("expected the fourth transport to be reused")
	}

	if id5 == id1 || id5 == id2 {
		t.Fatal("expected the fifth transport to be new")
	}

	transport1.Close()
	transport2.Close()
	transport3.Close()
	transport4.Close()
	transport5.Close()
	manager.Close()
}

func TestManagerRotateOnRequestLimit(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConcurrency:   "1",
		MaxConnections:   "1",
		HMaxRequestTimes: "1",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}

	transport1 := manager.GetTransport().(*ReuseTransport)
	id1 := transportID(transport1)

	transport1.Close()

	transport2 := manager.GetTransport().(*ReuseTransport)
	id2 := transportID(transport2)

	if id1 == id2 {
		t.Fatalf("expected new transport after request limit, got same id %d", id1)
	}

	transport2.Close()
	manager.Close()
}

func TestManagerRotateOnReusableSecs(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConcurrency:   "1",
		MaxConnections:   "1",
		HMaxRequestTimes: "100",
		HMaxReusableSecs: "1",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}

	transport1 := manager.GetTransport().(*ReuseTransport)
	id1 := transportID(transport1)

	time.Sleep(1100 * time.Millisecond)
	transport1.Close()

	transport2 := manager.GetTransport().(*ReuseTransport)
	id2 := transportID(transport2)

	if id1 == id2 {
		t.Fatalf("expected new transport after reusable timeout, got same id %d", id1)
	}

	transport2.Close()
	manager.Close()
}

func TestManagerRotateOnConnReuseLimit(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConcurrency:   "1",
		MaxConnections:   "1",
		CMaxReuseTimes:   "1",
		HMaxRequestTimes: "100",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}

	transport1 := manager.GetTransport().(*ReuseTransport)
	id1 := transportID(transport1)

	transport1.Close()

	transport2 := manager.GetTransport().(*ReuseTransport)
	id2 := transportID(transport2)

	if id1 != id2 {
		t.Fatalf("expected first reuse to use same transport, got %d and %d", id1, id2)
	}

	transport2.Close()

	transport3 := manager.GetTransport().(*ReuseTransport)
	id3 := transportID(transport3)

	if id3 == id2 {
		t.Fatalf("expected new transport after c-max-reuse-times limit, got same id %d", id3)
	}

	transport3.Close()
	manager.Close()
}

func TestManagerDropsEntryAfterRoundTripFailure(t *testing.T) {
	// Production config leaves xmux limits unset, so a pooled entry never
	// expires on its own. A transport-level failure must retire it, otherwise
	// every later request keeps being handed the same dead connection.
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{}, makeRoundTripperFactory(&created, true))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	first := manager.GetTransport().(*ReuseTransport)
	firstID := roundTripperID(first)

	req, err := http.NewRequest("POST", "https://example.com/xhttp", bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.RoundTrip(req); err == nil {
		t.Fatal("expected the failing transport to report an error")
	}
	first.Close()

	second := manager.GetTransport().(*ReuseTransport)
	secondID := roundTripperID(second)
	second.Close()

	if secondID == firstID {
		t.Fatalf("a dead pooled connection must not be handed out again, got transport %d twice", firstID)
	}
}

func TestManagerKeepsEntryAfterSuccessfulRoundTrip(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{}, makeRoundTripperFactory(&created, false))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	first := manager.GetTransport().(*ReuseTransport)
	firstID := roundTripperID(first)

	req, err := http.NewRequest("POST", "https://example.com/xhttp", bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := first.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	first.Close()

	second := manager.GetTransport().(*ReuseTransport)
	secondID := roundTripperID(second)
	second.Close()

	if secondID != firstID {
		t.Fatalf("a healthy connection must stay reusable, got transport %d then %d", firstID, secondID)
	}
}
