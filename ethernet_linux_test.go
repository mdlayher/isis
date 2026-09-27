//go:build linux

package isis_test

import (
	"net"
	"testing"

	"github.com/mdlayher/isis"
)

// ListenEthernet refuses an interface which cannot carry an Ethernet
// circuit before it opens a socket.
func TestListenEthernetRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ifi  *net.Interface
		err  string
	}{
		{
			name: "an interface with no link layer address",
			ifi: &net.Interface{
				Name: "test",
				MTU:  1500,
			},
			err: "isis: test has a link layer address of 0 octets, not the 6 an Ethernet circuit needs",
		},
		{
			name: "an interface with a link layer address of the wrong size",
			ifi: &net.Interface{
				Name:         "test",
				MTU:          1500,
				HardwareAddr: make([]byte, 8),
			},
			err: "isis: test has a link layer address of 8 octets, not the 6 an Ethernet circuit needs",
		},
		{
			name: "an MTU no larger than the LLC header",
			ifi: &net.Interface{
				Name:         "test",
				MTU:          3, // The LLC header's length.
				HardwareAddr: make([]byte, 6),
			},
			err: "isis: test has an MTU of 3, too small for the LLC header and a PDU",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e, err := isis.ListenEthernet(tt.ifi, nil)
			if err == nil {
				_ = e.Close()
				t.Fatal("expected an error, but opened a transport")
			}

			if got := err.Error(); got != tt.err {
				t.Fatalf("unexpected error: want %q, got %q", tt.err, got)
			}
		})
	}
}
