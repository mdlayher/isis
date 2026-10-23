//go:build interop && linux

package interop

import (
	"bytes"
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

// A hostConfig configures the library's end of the harness link.
type hostConfig struct {
	// Groups is passed straight to EthernetConfig: nil joins the IS-IS
	// destinations and a non-nil empty slice joins none.
	Groups []isis.SNPA

	// Padding is the Circuit's hello padding mode.
	Padding isis.PaddingMode

	// HelloInterval and HoldingMultiplier are the Circuit's timings. The
	// zero values are one second and three, matching what the FRR
	// template configures on the other end.
	HelloInterval     time.Duration
	HoldingMultiplier uint8

	// MD5Key, if set, authenticates the Circuit's hellos with RFC 5304
	// HMAC-MD5 under this key.
	MD5Key string
}

// A host is the library's own end of the harness link: a packet socket on
// the host end of the veth pair, one point to point Circuit over it, and
// the channels its hooks feed.
type host struct {
	c  *isis.Circuit
	tr *isis.EthernetTransport
	id isis.SystemID

	// v4 and v6 are the addresses this end advertises. v6 is the kernel's
	// link-local on the veth, which is what FRR reports back as the
	// neighbor's ipv6-link-local.
	v4, v6 netip.Addr

	adjC   chan isis.AdjacencyEvent
	pduC   chan isis.PDUEvent
	runC   chan error
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// startHost opens a packet socket on the host end of f's veth pair and
// runs a Circuit configured by cfg over it, torn down when t ends. ctx
// bounds the wait for the veth's link-local address.
func startHost(ctx context.Context, t *testing.T, f *frrtest.Instance, cfg hostConfig) *host {
	t.Helper()

	if cfg.HelloInterval == 0 {
		cfg.HelloInterval = 1 * time.Second
	}

	if cfg.HoldingMultiplier == 0 {
		cfg.HoldingMultiplier = 3
	}

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
		pduC: make(chan isis.PDUEvent, 4096),
		runC: make(chan error, 1),
	}

	h.tr, err = isis.ListenEthernet(ifi, &isis.EthernetConfig{Groups: cfg.Groups})
	if err != nil {
		t.Fatalf("failed to listen on %s: %v", oracle.Host, err)
	}

	var auth *isis.AuthConfig
	if cfg.MD5Key != "" {
		auth = &isis.AuthConfig{
			Type: isis.AuthTypeHMACMD5,
			Key:  []byte(cfg.MD5Key),
		}
	}

	h.c, err = isis.NewCircuit(h.tr, isis.CircuitConfig{
		SystemID:               id,
		AreaAddresses:          []isis.AreaAddress{area},
		Levels:                 isis.Level2Only,
		Type:                   isis.CircuitPointToPoint,
		HelloInterval:          cfg.HelloInterval,
		HoldingMultiplier:      cfg.HoldingMultiplier,
		LocalCircuitID:         hostCircuitID,
		ExtendedLocalCircuitID: hostExtendedCircuitID,
		IPv4Addresses:          []netip.Addr{h.v4},
		IPv6Addresses:          []netip.Addr{h.v6},
		Padding:                cfg.Padding,
		Auth:                   auth,

		OnAdjacency: func(_ *isis.Circuit, e isis.AdjacencyEvent) { h.adjC <- e },

		// A hook must return promptly, so a full channel drops rather than
		// stalling the Circuit. Raw aliases a buffer the Circuit reuses.
		OnPDU: func(_ *isis.Circuit, e isis.PDUEvent) {
			e.Raw = bytes.Clone(e.Raw)
			select {
			case h.pduC <- e:
			default:
			}
		},
	})
	if err != nil {
		_ = h.tr.Close()
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

// wantNoAdjacency requires that the Circuit has reported no adjacency
// state change.
func (h *host) wantNoAdjacency(t *testing.T) {
	t.Helper()

	select {
	case e := <-h.adjC:
		t.Fatalf("unexpected adjacency event: %+v", e)
	default:
	}
}

// waitReceivedHellos waits for the tap to record n point to point hellos
// received from the neighbor, whether or not they passed authentication,
// and fails t if ctx ends first. It returns every event it consumed on
// the way, in order and ending with the nth received hello, so a caller
// which inspects sent hellos too loses none of them; a caller wanting
// only the received hellos filters.
func (h *host) waitReceivedHellos(ctx context.Context, t *testing.T, n int) []isis.PDUEvent {
	t.Helper()

	var (
		out []isis.PDUEvent
		got int
	)

	for got < n {
		select {
		case e := <-h.pduC:
			out = append(out, e)
			if isReceivedHello(e) {
				got++
			}
		case <-ctx.Done():
			t.Fatalf("timed out after %d of %d received hellos: %v", got, n, ctx.Err())
			return nil
		}
	}

	return out
}

// tap drains everything the tap has recorded so far.
func (h *host) tap() []isis.PDUEvent {
	var out []isis.PDUEvent
	for {
		select {
		case e := <-h.pduC:
			out = append(out, e)
		default:
			return out
		}
	}
}

// isReceivedHello reports whether e is a point to point hello received
// from the neighbor.
func isReceivedHello(e isis.PDUEvent) bool {
	return e.Direction == isis.DirectionReceived && e.Header.Type == isis.PDUPointToPointHello
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
