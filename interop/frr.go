//go:build interop && linux

package interop

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/mdlayher/frrtest"
)

// frrVersion pins the FRR oracle release, enforced against the daemons'
// own reported version at startup. A silent oracle change must never be
// observable as a test result, since it would be indistinguishable from a
// regression in this library. Upgrades are therefore deliberate bumps of
// this constant together with the nix flake lock that supplies FRR to dev
// shells and CI.
const frrVersion = "10.7.0"

// oracle hosts the suite's FRR instances. isisd learns its interfaces
// through zebra and cannot stand alone, so both run.
var oracle = frrtest.Oracle{
	Version:   frrVersion,
	Daemons:   []string{"zebra", "isisd"},
	EnvPrefix: "ISIS_INTEROP",
	Host:      "isisi-host",
	Peer:      "isisi-frr",
}

// The identities of the two systems on the harness link. Both are in one
// area, since a Level 2 adjacency does not require that and the scenarios
// here are about the handshake rather than the hierarchy.
const (
	frrNET  = "49.0001.0000.0000.0002.00"
	hostNET = "49.0001.0000.0000.0001.00"
)

// An frrConfig parameterizes testdata/frr.conf.tmpl.
type frrConfig struct {
	// Interface is the FRR end of the veth pair and NET the network
	// entity title FRR runs as.
	Interface, NET string

	// HelloInterval is FRR's hello-interval in seconds and
	// HelloMultiplier its hello-multiplier: their product is the holding
	// time FRR advertises to us.
	HelloInterval, HelloMultiplier int
}

// defaultFRRConfig is the configuration every scenario starts from.
func defaultFRRConfig() frrConfig {
	return frrConfig{
		Interface:       oracle.Peer,
		NET:             frrNET,
		HelloInterval:   1,
		HelloMultiplier: 3,
	}
}

// startFRR renders cfg and starts an FRR instance running it, torn down
// when t ends. It returns once isisd is answering vtysh, failing t if ctx
// ends first.
func startFRR(ctx context.Context, t *testing.T, cfg frrConfig) *frrtest.Instance {
	t.Helper()

	f := oracle.Start(ctx, t, oracle.Render(t, "testdata/frr.conf.tmpl", cfg))
	if err := f.Poll(ctx, func() error {
		var v json.RawMessage
		return f.JSON(t, "show isis summary json", &v)
	}); err != nil {
		t.Fatalf("isisd never answered vtysh: %v", err)
	}

	return f
}

// An frrNeighbors is the narrow slice of `show isis neighbor detail json`
// this suite asserts on; FRR's full schema is deliberately not modeled.
type frrNeighbors struct {
	Areas []struct {
		Area     string         `json:"area"`
		Circuits []frrAdjacency `json:"circuits"`
	} `json:"areas"`
}

// An frrAdjacency is FRR's view of one adjacency: its record of what this
// library put on the wire.
type frrAdjacency struct {
	Circuit int `json:"circuit"`

	// Adj is the neighbor's name, which without a dynamic hostname is its
	// system identifier.
	Adj string `json:"adj"`

	Level     int    `json:"level"`
	ExpiresIn string `json:"expires-in"`

	Interface struct {
		Name        string `json:"name"`
		State       string `json:"state"`
		AdjFlaps    int    `json:"adj-flaps"`
		CircuitType string `json:"circuit-type"`
		Speaks      string `json:"speaks"`

		AreaAddress struct {
			ISONet string `json:"isonet"`
		} `json:"area-address"`

		IPv4Address struct {
			IPv4 string `json:"ipv4"`
		} `json:"ipv4-address"`

		IPv6LinkLocal struct {
			IPv6 string `json:"ipv6"`
		} `json:"ipv6-link-local"`
	} `json:"interface"`
}

// adjacencies returns every adjacency f currently holds. A circuit with no
// adjacency appears in FRR's output carrying nothing but its index, and is
// skipped.
func adjacencies(t *testing.T, f *frrtest.Instance) []frrAdjacency {
	t.Helper()

	var n frrNeighbors
	if err := f.JSON(t, "show isis neighbor detail json", &n); err != nil {
		t.Fatalf("failed to read FRR neighbors: %v", err)
	}

	var out []frrAdjacency
	for _, a := range n.Areas {
		for _, c := range a.Circuits {
			if c.Adj != "" {
				out = append(out, c)
			}
		}
	}

	return out
}

// awaitAdjacency polls until f reports exactly one adjacency in the given
// interface state, and returns its view of it, failing t if ctx ends
// first.
func awaitAdjacency(ctx context.Context, t *testing.T, f *frrtest.Instance, state string) frrAdjacency {
	t.Helper()

	var got frrAdjacency
	if err := f.Poll(ctx, func() error {
		adjs := adjacencies(t, f)
		if len(adjs) != 1 || adjs[0].Interface.State != state {
			return fmt.Errorf("FRR holds %d adjacencies: %+v", len(adjs), adjs)
		}

		got = adjs[0]
		return nil
	}); err != nil {
		t.Fatalf("no adjacency ever reached state %q: %v", state, err)
	}

	return got
}
