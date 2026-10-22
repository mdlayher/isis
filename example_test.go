package isis_test

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"

	"github.com/mdlayher/isis"
	"golang.org/x/sync/errgroup"
)

// A Circuit runs over a Transport on one interface. The caller gates its
// own liveness check on the adjacency events the Circuit reports, and
// reports back through SetUsable when that check changes state.
func ExampleCircuit() {
	ifi, err := net.InterfaceByName("eth0")
	if err != nil {
		log.Fatal(err)
	}

	t, err := isis.ListenEthernet(ifi, nil)
	if err != nil {
		log.Fatal(err)
	}

	area, id, err := isis.ParseNET("49.0001.0000.0000.0001.00")
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Run and every liveness check share one group, so all of them end
	// together and Wait returns only once each has.
	eg, ctx := errgroup.WithContext(ctx)

	// The hook runs on the Circuit's own goroutine, one event at a time, so
	// stop needs no lock. It ends the running liveness check, if any.
	stop := func() {}
	c, err := isis.NewCircuit(t, isis.CircuitConfig{
		SystemID:      id,
		AreaAddresses: []isis.AreaAddress{area},
		Levels:        isis.Level2Only,
		Type:          isis.CircuitPointToPoint,
		IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		IPv6Addresses: []netip.Addr{netip.MustParseAddr("fe80::1")},

		OnAdjacency: func(c *isis.Circuit, e isis.AdjacencyEvent) {
			switch e.State {
			case isis.AdjacencyUp:
				// Liveness starts once the adjacency is Up. A hook must
				// return promptly, so the check runs on a goroutine of its
				// own.
				lctx, lcancel := context.WithCancel(ctx)
				stop = lcancel
				eg.Go(func() error {
					checkLiveness(lctx, e.IPv4Addresses, func(usable bool) {
						c.SetUsable(e.Neighbor, usable)
					})

					return nil
				})
			case isis.AdjacencyDown:
				stop()
			}
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Run joins the group, beside any other work the caller adds to it.
	eg.Go(func() error { return c.Run(ctx) })

	// Run returns the context's error once the caller is interrupted, which
	// is a clean shutdown.
	if err := eg.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

// checkLiveness stands in for the caller's own liveness check of a
// neighbor at addrs, for which a BFD session is the usual choice. It calls
// report each time the neighbor becomes usable or unusable, and returns
// once ctx ends.
func checkLiveness(ctx context.Context, addrs []netip.Addr, report func(usable bool)) {
	// A real check opens a session to addrs here, calls report(false) when
	// that session fails, and calls report(true) when it recovers. This one
	// only ever finds the neighbor usable.
	log.Printf("checking liveness of %v", addrs)
	report(true)
	<-ctx.Done()
}
