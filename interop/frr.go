//go:build interop && linux

package interop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/mdlayher/frrtest"
	"github.com/mdlayher/isis"
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

	// NoHelloPadding turns FRR's default hello padding off. Left false,
	// FRR pads to the interface MTU, which is the case a receive buffer
	// sized to ISO 10589's ReceiveLSPBufferSize silently truncates.
	NoHelloPadding bool

	// MD5Password, if set, authenticates FRR's hellos with RFC 5304
	// HMAC-MD5 under this interface password.
	MD5Password string
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
// when t ends. It returns once isisd holds its IPv6 link-local address,
// failing t if ctx ends first. isisd advertises the address only once
// the kernel finishes duplicate address detection on it, so every hello a
// host started afterward receives carries it.
func startFRR(ctx context.Context, t *testing.T, cfg frrConfig) *frrtest.Instance {
	t.Helper()

	f := oracle.Start(ctx, t, oracle.Render(t, "testdata/frr.conf.tmpl", cfg))
	if err := f.Poll(ctx, func() error {
		var ifs frrInterfaces
		if err := f.JSON(t, "show isis interface detail json", &ifs); err != nil {
			return err
		}

		if len(ifs.linkLocal(t)) == 0 {
			return errors.New("isisd holds no IPv6 link-local address")
		}

		return nil
	}); err != nil {
		t.Fatalf("isisd never gained its IPv6 link-local address: %v", err)
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

// An frrInterfaces is the slice of `show isis interface detail json` this
// suite reads: FRR's own view of the addresses it advertises.
type frrInterfaces struct {
	Areas []struct {
		Circuits []struct {
			Interface struct {
				Name          string `json:"name"`
				IPv6LinkLocal struct {
					IPv6 string `json:"ipv6"`
				} `json:"ipv6-link-locals"`
			} `json:"interface"`
		} `json:"circuits"`
	} `json:"areas"`
}

// linkLocal returns the IPv6 link-local addresses ifs holds on
// oracle.Peer, without their prefix lengths.
func (ifs frrInterfaces) linkLocal(t *testing.T) []netip.Addr {
	t.Helper()

	var out []netip.Addr
	for _, a := range ifs.Areas {
		for _, c := range a.Circuits {
			if c.Interface.Name != oracle.Peer || c.Interface.IPv6LinkLocal.IPv6 == "" {
				continue
			}

			p, err := netip.ParsePrefix(c.Interface.IPv6LinkLocal.IPv6)
			if err != nil {
				t.Fatalf("failed to parse the link-local FRR reports: %v", err)
			}

			out = append(out, p.Addr())
		}
	}

	return out
}

// frrLinkLocal returns the IPv6 link-local addresses f holds on
// oracle.Peer, without their prefix lengths.
func frrLinkLocal(t *testing.T, f *frrtest.Instance) []netip.Addr {
	t.Helper()

	var ifs frrInterfaces
	if err := f.JSON(t, "show isis interface detail json", &ifs); err != nil {
		t.Fatalf("failed to read FRR interfaces: %v", err)
	}

	return ifs.linkLocal(t)
}

// frrSNPA returns the link layer address of oracle.Peer, as zebra reports
// it.
func frrSNPA(t *testing.T, f *frrtest.Instance) isis.SNPA {
	t.Helper()

	var ifs map[string]struct {
		HardwareAddress string `json:"hardwareAddress"`
	}

	if err := f.JSON(t, "show interface "+oracle.Peer+" json", &ifs); err != nil {
		t.Fatalf("failed to read FRR's interface: %v", err)
	}

	mac, err := net.ParseMAC(ifs[oracle.Peer].HardwareAddress)
	if err != nil || len(mac) != len(isis.SNPA{}) {
		t.Fatalf("failed to parse the hardware address FRR reports: %q", ifs[oracle.Peer].HardwareAddress)
	}

	return isis.SNPA(mac)
}
