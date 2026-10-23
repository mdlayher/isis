//go:build interop && linux

package interop

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/isis"
)

// holdingTime is what both ends advertise: the one second hello interval
// of the FRR template and the host, times a multiplier of three.
const holdingTime = 3 * time.Second

func TestFRRAdjacencyUp(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// FRR's own neighbor output reports this implementation in state Up.
	f := startFRR(ctx, t, defaultFRRConfig())
	h := startHost(ctx, t, f)

	e := h.waitAdjacency(ctx, t, isis.AdjacencyUp)

	if want := frrSystemID(t); e.Neighbor != want {
		t.Fatalf("unexpected neighbor: want %q, got %q", want, e.Neighbor)
	}

	if e.Levels != isis.Level2Only {
		t.Fatalf("unexpected levels: want %q, got %q", isis.Level2Only, e.Levels)
	}

	if diff := cmp.Diff([]isis.NLPID{isis.NLPIDIPv4, isis.NLPIDIPv6}, e.Protocols); diff != "" {
		t.Fatalf("unexpected protocols (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff([]string{"49.0001"}, stringsOf(e.AreaAddresses)); diff != "" {
		t.Fatalf("unexpected area addresses (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff([]string{f.Addresses().Peer[0].Addr().String()}, stringsOf(e.IPv4Addresses)); diff != "" {
		t.Fatalf("unexpected IPv4 addresses (-want +got):\n%s", diff)
	}

	// FRR's own view, which is the assertion that matters.
	adj := awaitAdjacency(ctx, t, f, "Up")

	if want := h.id.String(); adj.Adj != want {
		t.Fatalf("unexpected neighbor name: want %q, got %q", want, adj.Adj)
	}

	if adj.Level != 2 {
		t.Fatalf("unexpected level: want %d, got %d", 2, adj.Level)
	}

	if want := "L2"; adj.Interface.CircuitType != want {
		t.Fatalf("unexpected circuit type: want %q, got %q", want, adj.Interface.CircuitType)
	}

	if want := "IPv4, IPv6"; adj.Interface.Speaks != want {
		t.Fatalf("unexpected protocols: want %q, got %q", want, adj.Interface.Speaks)
	}

	if want := "49.0001"; adj.Interface.AreaAddress.ISONet != want {
		t.Fatalf("unexpected area address: want %q, got %q", want, adj.Interface.AreaAddress.ISONet)
	}

	if want := h.v4.String(); adj.Interface.IPv4Address.IPv4 != want {
		t.Fatalf("unexpected IPv4 address: want %q, got %q", want, adj.Interface.IPv4Address.IPv4)
	}

	if want := h.v6.String(); adj.Interface.IPv6LinkLocal.IPv6 != want {
		t.Fatalf("unexpected IPv6 link-local address: want %q, got %q", want, adj.Interface.IPv6LinkLocal.IPv6)
	}

	// FRR counts down the holding time this end advertised, so it can
	// never exceed it.
	expires, err := time.ParseDuration(adj.ExpiresIn)
	if err != nil {
		t.Fatalf("failed to parse the expiry FRR reports: %v", err)
	}

	if expires <= 0 || expires > holdingTime {
		t.Fatalf("FRR reports the adjacency expiring in %s, outside the advertised %s", expires, holdingTime)
	}
}

func TestFRRVersionPinned(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// The tripwire the harness already enforces against the daemon
	// binary, asserted again through the oracle's own output so a
	// mismatched vtysh cannot hide it.
	f := startFRR(ctx, t, defaultFRRConfig())

	out, err := f.Vtysh("show version")
	if err != nil {
		t.Fatalf("failed to run vtysh: %v: %s", err, out)
	}

	if want := "FRRouting " + frrVersion + " "; !strings.HasPrefix(string(out), want) {
		t.Fatalf("the oracle must be FRR %s, but reports: %q", frrVersion, out)
	}
}

// frrSystemID is the system identifier of the oracle's NET.
func frrSystemID(t *testing.T) isis.SystemID {
	t.Helper()

	_, id, err := isis.ParseNET(frrNET)
	if err != nil {
		t.Fatalf("failed to parse the FRR NET: %v", err)
	}

	return id
}

// stringsOf renders each of vs with String, for comparison.
func stringsOf[T fmt.Stringer](vs []T) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.String())
	}

	return out
}
