//go:build linux

package isis

import (
	"bytes"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// The tests in this file reach the unexported packet filter of the Linux
// Ethernet transport.

// The filter accepts a frame with the ISO SAPs and the IS-IS discriminator,
// and nothing else.
func Test_isisFilter(t *testing.T) {
	t.Parallel()

	// The software BPF machine does not implement the packet type
	// extension, so the program under test here is the rest of it,
	// sliced from the real instructions. Its two returns are the last
	// two, and every jump is relative to them, so the slice behaves
	// exactly as those instructions do in the kernel.
	vm, err := bpf.NewVM(isisFilter[2:])
	if err != nil {
		t.Fatalf("failed to build the BPF machine: %v", err)
	}

	// The filter reads only the two SAP octets and the discriminator, so
	// a few octets past it stand in for a whole PDU.
	body := []byte{0x14, 0x01, 0x00}

	tests := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{
			name:  "an IS-IS PDU",
			frame: llcFrame(llcHeader[:], discriminator, body),
			want:  true,
		},
		{
			name:  "a frame with an IP SAP",
			frame: llcFrame([]byte{0xaa, 0xaa, 0x03}, discriminator, body),
			want:  false,
		},
		{
			name:  "an ISO frame which is not IS-IS",
			frame: llcFrame(llcHeader[:], 0x82, body),
			want:  false,
		},
		{
			name:  "a frame too short for the discriminator",
			frame: llcHeader[:],
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			n, err := vm.Run(tt.frame)
			if err != nil {
				t.Fatalf("failed to run the filter: %v", err)
			}

			if got := n > 0; got != tt.want {
				t.Fatalf("unexpected acceptance: want %t, got %t", tt.want, got)
			}
		})
	}
}

// A packet socket is handed the interface's own outgoing multicast back,
// and the only thing standing between that and a Circuit hearing its own
// hellos is one jump offset: the filter tests the packet type first and
// jumps an outgoing frame to the drop.
func Test_isisFilterOwnTransmissions(t *testing.T) {
	t.Parallel()

	if _, err := bpf.Assemble(isisFilter); err != nil {
		t.Fatalf("failed to assemble the filter: %v", err)
	}

	load, ok := isisFilter[0].(bpf.LoadExtension)
	if !ok || load.Num != bpf.ExtType {
		t.Fatalf("the filter does not begin by loading the packet type: %v", isisFilter[0])
	}

	jump, ok := isisFilter[1].(bpf.JumpIf)
	if !ok {
		t.Fatalf("the packet type is not tested: %v", isisFilter[1])
	}

	if jump.Val != unix.PACKET_OUTGOING {
		t.Fatalf("unexpected packet type tested: want %d, got %d", unix.PACKET_OUTGOING, jump.Val)
	}

	// The drop is the last instruction, and a true jump from index one
	// lands on it.
	drop, ok := isisFilter[len(isisFilter)-1].(bpf.RetConstant)
	if !ok || drop.Val != 0 {
		t.Fatalf("the filter does not end in a drop: %v", isisFilter[len(isisFilter)-1])
	}

	if want, got := len(isisFilter)-1, 2+int(jump.SkipTrue); got != want {
		t.Fatalf("an outgoing frame does not jump to the drop: want index %d, got %d", want, got)
	}
}

// llcFrame returns an LLC header llc, then the discriminator d, then body.
func llcFrame(llc []byte, d byte, body []byte) []byte {
	b := bytes.Clone(llc)
	b = append(b, d)
	return append(b, body...)
}
