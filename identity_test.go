package isis_test

import (
	"testing"

	"github.com/mdlayher/isis"
)

func TestParseNET(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    string
		area string
		id   isis.SystemID
	}{
		{
			name: "a two octet area",
			s:    "49.0001.0000.0000.0001.00",
			area: "49.0001",
			id:   isis.SystemID{0, 0, 0, 0, 0, 1},
		},
		{
			name: "a one octet area",
			s:    "49.0000.0000.0002.00",
			area: "49",
			id:   isis.SystemID{0, 0, 0, 0, 0, 2},
		},
		{
			name: "periods are decoration",
			s:    "490001000000000001" + "00",
			area: "49.0001",
			id:   isis.SystemID{0, 0, 0, 0, 0, 1},
		},
		{
			name: "a full twenty octet NSAP",
			s:    "49.0001.0203.0405.0607.0809.0a0b.0000.0000.0003.00",
			area: "49.0001.0203.0405.0607.0809.0a0b",
			id:   isis.SystemID{0, 0, 0, 0, 0, 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			area, id, err := isis.ParseNET(tt.s)
			if err != nil {
				t.Fatalf("failed to parse NET: %v", err)
			}

			if got := area.String(); got != tt.area {
				t.Fatalf("unexpected area address: want %q, got %q", tt.area, got)
			}

			if d := diff(t, tt.id, id); d != "" {
				t.Fatalf("unexpected system ID (-want +got):\n%s", d)
			}
		})
	}
}

func TestParseNETRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, s string
	}{
		{
			name: "not hexadecimal",
			s:    "49.0001.0000.0000.000z.00",
		},
		{
			name: "an odd number of digits",
			s:    "49.0001.0000.0000.0001.0",
		},
		{
			name: "no area address",
			s:    "0000.0000.0001.00",
		},
		{
			name: "a nonzero NSEL",
			s:    "49.0001.0000.0000.0001.01",
		},
		{
			name: "past a twenty octet NSAP",
			s:    "49.0001.0203.0405.0607.0809.0a0b.0c.0000.0000.0003.00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			area, id, err := isis.ParseNET(tt.s)
			if err == nil {
				t.Fatalf("expected an error, but parsed %s and %s", area, id)
			}

			t.Logf("err: %v", err)
		})
	}
}

func TestIdentityStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "system ID",
			got:  isis.SystemID{0, 0, 0, 0, 0, 1}.String(),
			want: "0000.0000.0001",
		},
		{
			name: "LSP ID",
			got:  isis.LSPID{SystemID: isis.SystemID{0, 0, 0, 0, 0, 1}}.String(),
			want: "0000.0000.0001.00-00",
		},
		{
			name: "pseudonode LSP ID fragment",
			got: isis.LSPID{
				SystemID:   isis.SystemID{0, 0, 0, 0, 0, 1},
				Pseudonode: 2,
				Fragment:   3,
			}.String(),
			want: "0000.0000.0001.02-03",
		},
		{
			name: "SNPA",
			got:  isis.AllISs().String(),
			want: "09:00:2b:00:00:05",
		},
		{
			name: "level",
			got:  isis.Level2.String(),
			want: "Level 2",
		},
		{
			name: "level set",
			got:  isis.Level1And2.String(),
			want: "Level 1 and 2",
		},
		{
			name: "topology",
			got:  isis.TopologyIPv6Unicast.String(),
			want: "IPv6 unicast",
		},
		{
			name: "unnamed topology",
			got:  isis.Topology(3).String(),
			want: "MT 3",
		},
		{
			name: "circuit type",
			got:  isis.CircuitPointToPoint.String(),
			want: "point to point",
		},
		{
			name: "unset circuit type",
			got:  isis.CircuitType(0).String(),
			want: "unknown(0)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.got != tt.want {
				t.Fatalf("unexpected string: want %q, got %q", tt.want, tt.got)
			}
		})
	}
}

func TestLevelSetHas(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		s      isis.LevelSet
		l1, l2 bool
	}{
		{
			name: "Level 1 only",
			s:    isis.Level1Only,
			l1:   true,
		},
		{
			name: "Level 2 only",
			s:    isis.Level2Only,
			l2:   true,
		},
		{
			name: "both levels",
			s:    isis.Level1And2,
			l1:   true,
			l2:   true,
		},
		{
			name: "no levels",
			s:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.s.Has(isis.Level1); got != tt.l1 {
				t.Fatalf("unexpected Level 1 membership: want %t, got %t", tt.l1, got)
			}

			if got := tt.s.Has(isis.Level2); got != tt.l2 {
				t.Fatalf("unexpected Level 2 membership: want %t, got %t", tt.l2, got)
			}
		})
	}
}

func TestNewAreaAddressRejects(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, 21} {
		a, err := isis.NewAreaAddress(make([]byte, n))
		if err == nil {
			t.Fatalf("expected an error for %d octets, but built %s", n, a)
		}

		t.Logf("err: %v", err)
	}
}
