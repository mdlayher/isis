//go:build linux

package isis

import (
	"fmt"
	"net"
	"slices"
	"sync"

	"github.com/mdlayher/packet"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// llcLen is the length of the 802.2 LLC header every IS-IS frame carries.
const llcLen = 3

// llcHeader is that header: DSAP 0xFE, SSAP 0xFE, and control 0x03,
// unnumbered information (ISO 10589 clause 8.4.8). It is never modified.
var llcHeader = [llcLen]byte{0xfe, 0xfe, 0x03}

// isisFilter is the classic BPF program every Ethernet transport applies.
// The socket is a datagram socket, so the kernel has already stripped the
// Ethernet header and the program sees a frame starting at the LLC
// header. It is never modified.
//
// The first test is the one which is easy to leave out: a packet socket
// is handed the interface's own outgoing multicast back, so without it an
// Instance hears its own hellos.
var isisFilter = []bpf.Instruction{
	// 0: this system's own transmissions, echoed back.
	bpf.LoadExtension{Num: bpf.ExtType},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.PACKET_OUTGOING, SkipTrue: 5},

	// 2: DSAP and SSAP, which are 0xFE for ISO network layer protocols.
	bpf.LoadAbsolute{Off: 0, Size: 2},
	bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0xfefe, SkipTrue: 3},

	// 4: the intradomain routeing protocol discriminator, past the three
	// octet LLC header.
	bpf.LoadAbsolute{Off: llcLen, Size: 1},
	bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: discriminator, SkipTrue: 1},

	// 6: accept the whole frame, or drop it.
	bpf.RetConstant{Val: 0xffffffff},
	bpf.RetConstant{Val: 0},
}

// An EthernetTransport is a Transport over one Ethernet interface, and the
// implementation for a real link. It is an AF_PACKET datagram socket bound
// to ETH_P_802_2, filtered to IS-IS PDUs, joined to the IS-IS link layer
// multicast groups, and framed with the 802.2 LLC header of ISO 10589
// clause 8.4.8.
//
// The socket needs CAP_NET_RAW. Nothing here touches netlink or knows
// what a route is: an EthernetTransport carries PDUs and nothing else.
type EthernetTransport struct {
	c      *packet.Conn
	local  SNPA
	maxPDU int
	groups []SNPA

	// rmu and wmu serialize ReadPDU and WritePDU respectively, so a reader
	// never waits on a writer. Each is held across the socket call as well
	// as the frame assembly, because the socket call is the work it exists
	// to serialize: the buffer is in use until the call returns.
	rmu, wmu sync.Mutex

	// rb and wb are the receive and transmit frame buffers, guarded by rmu
	// and wmu. A frame is the LLC header and the PDU together, so neither
	// direction can use the caller's buffer as it stands.
	rb, wb []byte
}

var _ Transport = (*EthernetTransport)(nil)

// ListenEthernet opens an Ethernet transport on ifi. A nil cfg is the
// zero EthernetConfig.
//
// The PDU size comes from the interface MTU, not from ISO 10589's
// ReceiveLSPBufferSize of 1492: a neighbor may pad its hellos to the MTU,
// and a smaller buffer would truncate them.
func ListenEthernet(ifi *net.Interface, cfg *EthernetConfig) (*EthernetTransport, error) {
	if cfg == nil {
		cfg = &EthernetConfig{}
	}

	if len(ifi.HardwareAddr) != len(SNPA{}) {
		return nil, fmt.Errorf("isis: %s has a link layer address of %d octets, not the %d an Ethernet circuit needs", ifi.Name, len(ifi.HardwareAddr), len(SNPA{}))
	}

	if ifi.MTU <= llcLen {
		return nil, fmt.Errorf("isis: %s has an MTU of %d, too small for the LLC header and a PDU", ifi.Name, ifi.MTU)
	}

	filter, err := bpf.Assemble(isisFilter)
	if err != nil {
		return nil, fmt.Errorf("isis: failed to assemble the packet filter: %w", err)
	}

	// The kernel classifies every 802.3 framed IS-IS frame as
	// ETH_P_802_2, so that is what receives them. It is also what makes
	// transmission correct: the kernel's eth_header writes the frame
	// length into the type field for ETH_P_802_2 rather than the protocol
	// number, which is the 802.3 length field an IS-IS frame needs.
	//
	// packet.Listen applies the filter before bind, so no frame reaches
	// the socket unfiltered.
	c, err := packet.Listen(ifi, packet.Datagram, unix.ETH_P_802_2, &packet.Config{Filter: filter})
	if err != nil {
		return nil, fmt.Errorf("isis: failed to open a packet socket on %s: %w", ifi.Name, err)
	}

	// A copy, so a caller editing its slice later cannot change what
	// Groups reports.
	groups := slices.Clone(cfg.Groups)
	if groups == nil {
		groups = []SNPA{AllISs(), AllL1ISs(), AllL2ISs()}
	}

	// Close drops every membership the Conn holds, so the error path
	// below needs no matching LeaveGroup.
	for _, g := range groups {
		if err := c.JoinGroup(g[:]); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("isis: failed to join %s on %s: %w", g, ifi.Name, err)
		}
	}

	return &EthernetTransport{
		c:      c,
		local:  SNPA(ifi.HardwareAddr),
		maxPDU: ifi.MTU - llcLen,
		groups: groups,
		rb:     make([]byte, ifi.MTU),
		wb:     make([]byte, 0, ifi.MTU),
	}, nil
}

// ReadPDU implements Transport.
func (e *EthernetTransport) ReadPDU(b []byte) (int, SNPA, error) {
	e.rmu.Lock()
	defer e.rmu.Unlock()

	n, addr, err := e.c.ReadFrom(e.rb)
	if err != nil {
		return 0, SNPA{}, err
	}

	// The filter has already checked the LLC header in the kernel, so a
	// frame failing here is a filter fault rather than ordinary traffic.
	// It is still a drop and not a fatal error: nothing on a shared link
	// is worth tearing a Circuit down for.
	if n < llcLen || [llcLen]byte(e.rb[:llcLen]) != llcHeader {
		return 0, SNPA{}, fmt.Errorf("%w: LLC header %x", ErrDropped, e.rb[:min(n, llcLen)])
	}

	pdu := e.rb[llcLen:n]
	if len(pdu) > len(b) {
		return 0, SNPA{}, fmt.Errorf("%w: %d octet PDU does not fit a %d octet buffer", ErrDropped, len(pdu), len(b))
	}

	a, ok := addr.(*packet.Addr)
	if !ok || len(a.HardwareAddr) != len(SNPA{}) {
		return 0, SNPA{}, fmt.Errorf("%w: source address %s is not a six octet link layer address", ErrDropped, addr)
	}

	return copy(b, pdu), SNPA(a.HardwareAddr), nil
}

// WritePDU implements Transport.
func (e *EthernetTransport) WritePDU(dst SNPA, b []byte) error {
	if len(b) > e.maxPDU {
		return fmt.Errorf("isis: %d octet PDU is over the link's %d", len(b), e.maxPDU)
	}

	e.wmu.Lock()
	defer e.wmu.Unlock()

	// One buffer of LLC header and PDU. The 802.3 length field is the
	// kernel's to write, because the socket's protocol is ETH_P_802_2.
	e.wb = append(append(e.wb[:0], llcHeader[:]...), b...)

	_, err := e.c.WriteTo(e.wb, &packet.Addr{HardwareAddr: dst[:]})
	return err
}

// MaxPDULen implements Transport: the interface MTU less the LLC header.
func (e *EthernetTransport) MaxPDULen() int { return e.maxPDU }

// LocalSNPA implements Transport: the interface's own link layer address.
func (e *EthernetTransport) LocalSNPA() SNPA { return e.local }

// Close implements Transport.
func (e *EthernetTransport) Close() error { return e.c.Close() }

// Groups reports the link layer multicast destinations this
// EthernetTransport joined, in the order it joined them. A caller which
// asked for none sees none, which is what makes the membership observable.
func (e *EthernetTransport) Groups() []SNPA { return slices.Clone(e.groups) }
