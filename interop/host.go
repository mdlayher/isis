//go:build interop && linux

package interop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/frrtest"
	"github.com/mdlayher/isis"
)

// timeout bounds each test's waits, through the context the test derives
// from it. Nothing here runs under a synthetic clock, so it is real time
// and generous.
const timeout = 60 * time.Second

// The circuit identifiers this end runs with. Both are fixed rather than
// random so a test can assert on what FRR echoes back.
const (
	hostCircuitID         = 1
	hostExtendedCircuitID = 1
)

// A host is the library's own end of the harness link: a packet socket on
// the host end of the veth pair, one point to point Circuit over it, and
// the channel its adjacency hook feeds.
type host struct {
	c  *isis.Circuit
	id isis.SystemID

	// v4 and v6 are the addresses this end advertises. v6 is the kernel's
	// link-local on the veth, which is what FRR reports back as the
	// neighbor's ipv6-link-local.
	v4, v6 netip.Addr

	adjC   chan isis.AdjacencyEvent
	runC   chan error
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// startHost opens a packet socket on the host end of f's veth pair and
// runs a Circuit over it, torn down when t ends. ctx bounds the wait for
// the veth's link-local address.
func startHost(ctx context.Context, t *testing.T, f *frrtest.Instance) *host {
	t.Helper()

	area, id, err := isis.ParseNET(hostNET)
	if err != nil {
		t.Fatalf("failed to parse the host NET: %v", err)
	}

	ifi, err := net.InterfaceByName(oracle.Host)
	if err != nil {
		t.Fatalf("failed to find %s: %v", oracle.Host, err)
	}

	h := &host{
		id:   id,
		v4:   f.Addresses().Host[0].Addr(),
		v6:   linkLocal(ctx, t, ifi),
		adjC: make(chan isis.AdjacencyEvent, 64),
		runC: make(chan error, 1),
	}

	tr, err := isis.ListenEthernet(ifi, nil)
	if err != nil {
		t.Fatalf("failed to listen on %s: %v", oracle.Host, err)
	}

	h.c, err = isis.NewCircuit(tr, isis.CircuitConfig{
		SystemID:               id,
		AreaAddresses:          []isis.AreaAddress{area},
		Levels:                 isis.Level2Only,
		Type:                   isis.CircuitPointToPoint,
		HelloInterval:          1 * time.Second,
		HoldingMultiplier:      3,
		LocalCircuitID:         hostCircuitID,
		ExtendedLocalCircuitID: hostExtendedCircuitID,
		IPv4Addresses:          []netip.Addr{h.v4},
		IPv6Addresses:          []netip.Addr{h.v6},

		OnAdjacency: func(_ *isis.Circuit, e isis.AdjacencyEvent) { h.adjC <- e },
	})
	if err != nil {
		_ = tr.Close()
		t.Fatalf("failed to build circuit: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	h.cancel = cancel
	h.wg.Go(func() { h.runC <- h.c.Run(ctx) })

	t.Cleanup(func() { h.stop(t) })
	return h
}

// stop cancels the Circuit and waits for Run to return, which closes the
// packet socket. It is idempotent, so a test may stop the Circuit early
// and still leave the cleanup in place.
func (h *host) stop(t *testing.T) {
	t.Helper()

	h.cancel()
	h.wg.Wait()

	select {
	case err := <-h.runC:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("unexpected run error: %v", err)
		}
	default:
		// Already stopped and reported by an earlier call.
	}
}

// waitAdjacency waits for the Circuit to report the adjacency in want,
// passing over the states it reaches on the way, and fails t if ctx ends
// first.
func (h *host) waitAdjacency(ctx context.Context, t *testing.T, want isis.AdjacencyState) isis.AdjacencyEvent {
	t.Helper()

	for {
		select {
		case e := <-h.adjC:
			t.Logf("adjacency %s: neighbor %s levels %s reason %q", e.State, e.Neighbor, e.Levels, e.Reason)
			if e.State == want {
				return e
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for adjacency state %q: %v", want, ctx.Err())
			return isis.AdjacencyEvent{}
		}
	}
}

// linkLocal returns the interface's IPv6 link-local address, waiting for
// the kernel to finish duplicate address detection on it, and fails t if
// ctx ends first.
func linkLocal(ctx context.Context, t *testing.T, ifi *net.Interface) netip.Addr {
	t.Helper()

	var got netip.Addr
	if err := frrtest.Poll(ctx, func() error {
		addrs, err := ifi.Addrs()
		if err != nil {
			return err
		}

		for _, a := range addrs {
			p, ok := a.(*net.IPNet)
			if !ok {
				continue
			}

			addr, ok := netip.AddrFromSlice(p.IP)
			if !ok || !addr.Is6() || addr.Is4In6() || !addr.IsLinkLocalUnicast() {
				continue
			}

			got = addr.WithZone("")
			return nil
		}

		return fmt.Errorf("%s has no usable IPv6 link-local address", ifi.Name)
	}); err != nil {
		t.Fatalf("the veth never gained a usable IPv6 link-local address: %v", err)
	}

	return got
}
