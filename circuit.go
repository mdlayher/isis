package isis

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

// A Direction is which way a PDU crossed a Circuit. The zero value is not
// valid.
type Direction uint8

// The directions.
const (
	_ Direction = iota
	DirectionReceived
	DirectionSent
)

// String returns the name of a Direction.
func (d Direction) String() string {
	switch d {
	case DirectionReceived:
		return "received"
	case DirectionSent:
		return "sent"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(d))
	}
}

// A PDUEvent reports one PDU crossing a Circuit, for audit and
// diagnostics. Every PDU a Circuit sends or receives is reported once,
// whatever its type, including a received PDU whose common header fails
// validation and a sent PDU whose write failed. A hello which could not
// be built never reaches the link and is not reported.
type PDUEvent struct {
	// Direction is which way the PDU crossed.
	Direction Direction

	// SNPA is the link layer address a received PDU came from, or the
	// destination a sent PDU went to.
	SNPA SNPA

	// Header is the PDU's decoded common header. It is the zero value for
	// a received PDU whose common header failed validation.
	Header Header

	// Raw is the PDU as it crossed the wire. It aliases a buffer the
	// Circuit reuses, so copy it to retain it past the hook's return.
	Raw []byte

	// Err is nil for a PDU which was received or written cleanly. On a
	// received event it is otherwise the error its common header failed
	// validation with, and the Circuit drops the PDU. On a sent event it
	// is the Transport's write error, and the PDU may not have reached
	// the link.
	Err error
}

const (
	// defaultHelloInterval is ISISHelloTimer, the pause between hellos on
	// a Circuit (ISO 10589 clause 11.2). FRR's hello-interval defaults to
	// the same three seconds.
	defaultHelloInterval = 3 * time.Second

	// defaultHoldingMultiplier is ISISHoldingMultiplier: how many hello
	// intervals of silence a neighbor waits before declaring this system
	// down. ISO 10589 uses three on a point to point Circuit and ten on a
	// broadcast one; FRR's hello-multiplier is ten for both, so ten is
	// what interoperates without configuration.
	defaultHoldingMultiplier = 10
)

// A CircuitConfig configures a Circuit. SystemID, AreaAddresses, Levels,
// and Type are required and every other field has a default or is
// optional. Configuration is immutable once the Circuit is built.
type CircuitConfig struct {
	// SystemID is this system's six octet identifier, unique in the
	// routing domain. It must be nonzero.
	SystemID SystemID

	// AreaAddresses are the areas this system claims, advertised in every
	// hello. At least one is required.
	AreaAddresses []AreaAddress

	// Levels is the set of levels the Circuit runs. It is required.
	Levels LevelSet

	// Protocols are the network layer protocols this system routes,
	// advertised in every hello as RFC 1195 section 5.2 requires. Each
	// needs an interface address of its family. The zero value is IPv4
	// and IPv6.
	Protocols []NLPID

	// Type is the kind of link the Circuit attaches to. It must be
	// CircuitPointToPoint. CircuitBroadcast returns an error wrapping
	// errors.ErrUnsupported.
	Type CircuitType

	// HelloInterval is the pause between hellos, reduced by up to a
	// quarter on each transmission so Circuits do not synchronize (ISO
	// 10589 clause 10.1). The zero value is three seconds.
	HelloInterval time.Duration

	// HoldingMultiplier is how many hello intervals of silence a neighbor
	// waits before declaring this system down. The advertised holding
	// time is the product of the two, rounded up to whole seconds and
	// clamped to the wire's 16 bits. The zero value is ten.
	HoldingMultiplier uint8

	// LocalCircuitID is the one octet circuit identifier of ISO 10589
	// clause 9.7, which must be unique among this system's circuits.
	LocalCircuitID uint8

	// ExtendedLocalCircuitID is the four octet circuit identifier of RFC
	// 5303 section 3.1, which a point to point Circuit advertises in its
	// three way adjacency TLV. It is unique on this system and stable for
	// the life of the Circuit. A neighbor learns this system restarted by
	// seeing it change, so the zero value is a random value rather than a
	// fixed one.
	ExtendedLocalCircuitID uint32

	// IPv4Addresses and IPv6Addresses are this end's interface addresses,
	// advertised in every hello. A Circuit advertising IPv4 needs at least
	// one IPv4 address, since RFC 3787 section 10 requires the IPv4 TLV
	// for interoperation, and one advertising IPv6 needs at least one
	// IPv6 address, all link-local, which is what RFC 5308 section 3
	// permits in a hello. A family with no addresses sends no TLV.
	IPv4Addresses, IPv6Addresses []netip.Addr

	// OnPDU, if set, observes every PDU in both directions, for audit and
	// diagnostics. It steers nothing.
	//
	// The hook runs on the goroutine running Run and must return
	// promptly: a stalled hook stalls the Circuit's hellos. A hook which
	// must block does that work on a new goroutine. c names the Circuit
	// which fired, so one hook function may serve many.
	OnPDU func(c *Circuit, e PDUEvent)

	// Logger, if set, records the Circuit starting at Info, a hello which
	// cannot be built at Error, and dropped PDUs, failed writes, and a
	// Transport which fails to close at Debug. nil discards everything.
	Logger *slog.Logger
}

// A Circuit is one system's attachment to a single link: it sends that
// link's hellos over its Transport and reports every PDU in both
// directions to CircuitConfig.OnPDU. NewCircuit builds one and Run runs
// it.
//
// Every field is owned by the goroutine running Run, so a Circuit must
// not be touched from a hook beyond comparing its identity.
type Circuit struct {
	t       Transport
	cfg     CircuitConfig
	log     *slog.Logger
	started atomic.Bool

	// helloAt is when the next hello is due.
	helloAt time.Time

	// hello is the point to point hello the Circuit sends, built and
	// proven to fit the link by NewCircuit. Only its last TLV, the three
	// way adjacency, changes from one hello to the next.
	hello *PointToPointHello

	// wb is the reused transmit marshal buffer.
	wb []byte
}

// NewCircuit validates the configuration and produces a Circuit over t.
// Nothing runs until Run, and ownership of t passes only when Run is
// called: a caller which never reaches Run closes t itself.
func NewCircuit(t Transport, c CircuitConfig) (*Circuit, error) {
	if t == nil {
		return nil, errors.New("isis: a circuit needs a transport")
	}

	if c.SystemID == (SystemID{}) {
		return nil, errors.New("isis: system ID must be nonzero")
	}

	if len(c.AreaAddresses) == 0 {
		return nil, errors.New("isis: at least one area address is required")
	}

	if c.Levels == 0 {
		return nil, errors.New("isis: circuit levels are required")
	}

	if c.Levels > Level1And2 {
		return nil, fmt.Errorf("isis: level set %d does not exist", uint8(c.Levels))
	}

	if len(c.Protocols) == 0 {
		c.Protocols = []NLPID{NLPIDIPv4, NLPIDIPv6}
	}

	switch c.Type {
	case 0:
		return nil, errors.New("isis: circuit type is required")
	case CircuitPointToPoint:
	case CircuitBroadcast:
		return nil, fmt.Errorf("isis: %s circuits are not implemented yet: %w", c.Type, errors.ErrUnsupported)
	default:
		return nil, fmt.Errorf("isis: circuit type %d does not exist", uint8(c.Type))
	}

	if c.HelloInterval == 0 {
		c.HelloInterval = defaultHelloInterval
	}

	if c.HelloInterval < 0 {
		return nil, fmt.Errorf("isis: hello interval must be positive: %s", c.HelloInterval)
	}

	if c.HoldingMultiplier == 0 {
		c.HoldingMultiplier = defaultHoldingMultiplier
	}

	if n := t.MaxPDULen(); n < headerLen {
		return nil, fmt.Errorf("isis: transport carries %d octets, too few for any PDU", n)
	}

	// RFC 5303 section 3.1 makes the extended local circuit ID the
	// evidence a neighbor uses to notice this system restarted, so a
	// caller which does not choose one gets a value which will differ
	// across restarts.
	for c.ExtendedLocalCircuitID == 0 {
		c.ExtendedLocalCircuitID = rand.Uint32()
	}

	// Configuration is immutable once built, so the slices are the
	// Circuit's own rather than the caller's.
	c.AreaAddresses = slices.Clone(c.AreaAddresses)
	c.Protocols = slices.Clone(c.Protocols)
	c.IPv4Addresses = slices.Clone(c.IPv4Addresses)
	c.IPv6Addresses = slices.Clone(c.IPv6Addresses)

	if slices.Contains(c.Protocols, NLPIDIPv4) && len(c.IPv4Addresses) == 0 {
		return nil, errors.New("isis: IPv4 is advertised but no IPv4 address is set")
	}

	if slices.Contains(c.Protocols, NLPIDIPv6) && len(c.IPv6Addresses) == 0 {
		return nil, errors.New("isis: IPv6 is advertised but no IPv6 address is set")
	}

	log := c.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	circuit := &Circuit{
		t:   t,
		cfg: c,
		log: log.With("system_id", c.SystemID.String(), "circuit", c.LocalCircuitID),
	}

	// Build and prove the hello the Circuit sends, so a bad configuration
	// is an error here rather than a failure on every hello.
	if err := circuit.buildHello(); err != nil {
		return nil, err
	}

	return circuit, nil
}

// buildHello builds the Circuit's point to point hello from its
// configuration and proves it encodes within the link's PDU size.
func (c *Circuit) buildHello() error {
	areas, err := AreaAddressesTLV(c.cfg.AreaAddresses)
	if err != nil {
		return err
	}

	protocols, err := ProtocolsSupportedTLV(c.cfg.Protocols)
	if err != nil {
		return err
	}

	// ISO 10589 clause 8.2.3 pads every hello to the link's full PDU
	// size, so an adjacency forms only over a link which carries one.
	c.hello = &PointToPointHello{
		Levels:         c.cfg.Levels,
		SourceID:       c.cfg.SystemID,
		HoldingTime:    c.holdingTime(),
		LocalCircuitID: c.cfg.LocalCircuitID,
		TLVs:           []TLV{areas, protocols},
		PadTo:          c.t.MaxPDULen(),
	}

	if len(c.cfg.IPv4Addresses) > 0 {
		v4, err := IPv4InterfaceAddressesTLV(c.cfg.IPv4Addresses)
		if err != nil {
			return err
		}

		c.hello.TLVs = append(c.hello.TLVs, v4)
	}

	if len(c.cfg.IPv6Addresses) > 0 {
		v6, err := IPv6InterfaceAddressesTLV(c.cfg.IPv6Addresses)
		if err != nil {
			return err
		}

		for _, a := range c.cfg.IPv6Addresses {
			if !a.IsLinkLocalUnicast() {
				return fmt.Errorf("isis: IPv6 interface address %s is not link-local", a)
			}
		}

		c.hello.TLVs = append(c.hello.TLVs, v6)
	}

	// RFC 5303 section 3.1 requires the three way adjacency TLV in every
	// point to point hello of a system which implements it. Its slot is
	// last, and appendPointToPointHello fills it before each hello.
	c.hello.TLVs = append(c.hello.TLVs, TLV{})

	b, err := c.appendPointToPointHello(nil)
	if err != nil {
		return err
	}

	if n := c.t.MaxPDULen(); len(b) > n {
		return fmt.Errorf("isis: hello is %d octets, more than the transport's %d", len(b), n)
	}

	return nil
}

// Run runs the Circuit until ctx is canceled or its Transport fails: a
// hello at once and another each hello interval after, with every PDU in
// both directions reported to OnPDU. Cancellation sends a last hello
// advertising three way Down, so a neighbor leaves Up at once rather than
// after a holding time (RFC 5303 section 3.2). Every exit closes the
// Transport and waits for the reader goroutine. Nothing retries: a caller
// wanting the Circuit back builds a fresh one.
//
// Run always returns a non-nil error:
//
//   - ctx's error, once canceled. A non-nil ctx.Err() marks a clean
//     shutdown even when a Transport failure raced it.
//   - The Transport's read error, wrapped with the circuit ID.
//   - An error when Run was already called, which touches nothing.
func (c *Circuit) Run(ctx context.Context) error {
	if !c.started.CompareAndSwap(false, true) {
		return errors.New("isis: circuit is already running or has run")
	}

	// The group's context ends when the caller cancels or the reader
	// fails, and Run returns only after Wait has joined the reader.
	eg, egctx := errgroup.WithContext(ctx)
	pduC := make(chan receivedPDU)
	eg.Go(func() error { return c.read(egctx, pduC) })

	// A cancellation sends the last hello before closing the Transport; a
	// failed Transport has nowhere to send it.
	const (
		withFarewell    = true
		withoutFarewell = false
	)

	c.log.Info("circuit running", "levels", c.cfg.Levels)

	// The Circuit greets the link as soon as it runs, and sending that
	// hello schedules the next.
	c.transmit(ctx, time.Now())

	t := time.NewTimer(time.Until(c.nextDeadline()))
	defer t.Stop()

	for {
		select {
		case <-egctx.Done():
			// Closing the Transport releases a reader waiting on a read. A
			// cancellation wins a race with a reader failure, whose error
			// is then the teardown's own.
			if err := ctx.Err(); err != nil {
				c.shutdown(ctx, withFarewell)
				_ = eg.Wait()
				return err
			}

			c.shutdown(ctx, withoutFarewell)
			return eg.Wait()
		case <-t.C:
			// Next tick.
		case p := <-pduC:
			c.receive(ctx, p)
		}

		// Whatever woke the Circuit, anything due runs before it sleeps
		// again, and the timer is rearmed for the next deadline.
		c.runDue(ctx, time.Now())
		t.Reset(time.Until(c.nextDeadline()))
	}
}

// A receivedPDU is one PDU the reader handed to the goroutine running Run.
type receivedPDU struct {
	src SNPA
	pdu []byte
}

// read is the Circuit's reader goroutine: it copies each PDU the
// Transport delivers and forwards it to the goroutine running Run until
// ctx ends, then returns nil. A read error wrapping ErrDropped records a
// frame the Transport discarded; any other read error is terminal for the
// Circuit, and read returns it naming the Circuit.
func (c *Circuit) read(ctx context.Context, pduC chan<- receivedPDU) error {
	buf := make([]byte, c.t.MaxPDULen())
	for {
		n, src, err := c.t.ReadPDU(buf)
		if err != nil {
			// Run closes the Transport only after ctx ends, so a read
			// error after that is the teardown's own.
			if ctx.Err() != nil {
				return nil
			}

			if errors.Is(err, ErrDropped) {
				if c.log.Enabled(ctx, slog.LevelDebug) {
					c.log.Debug("dropped frame", "err", err)
				}

				continue
			}

			return fmt.Errorf("isis: circuit %d transport read failed: %w", c.cfg.LocalCircuitID, err)
		}

		// A parsed PDU's TLV values alias these octets and the goroutine
		// running Run holds them past the next read, so each PDU is copied
		// out of the reused buffer.
		select {
		case pduC <- receivedPDU{src: src, pdu: bytes.Clone(buf[:n])}:
		case <-ctx.Done():
			return nil
		}
	}
}

// The core of a Circuit is receive, runDue, nextDeadline, and shutdown.
// None of them starts a goroutine or waits on a read, so one goroutine can
// drive any number of Circuits through them: Run drives one.

// receive reports one PDU to the tap. A Circuit acts on no PDU it
// receives: each is reported and dropped.
func (c *Circuit) receive(ctx context.Context, p receivedPDU) {
	hdr, err := ParseHeader(p.pdu)
	c.tap(PDUEvent{
		Direction: DirectionReceived,
		SNPA:      p.src,
		Header:    hdr,
		Raw:       p.pdu,
		Err:       err,
	})

	if err != nil {
		if c.log.Enabled(ctx, slog.LevelDebug) {
			c.log.Debug("dropped PDU", "src", p.src, "err", err)
		}

		return
	}

	// TODO(mdlayher): act on a point to point hello, which is where a
	// Circuit forms its adjacency.
}

// runDue sends the hello if it has come due.
func (c *Circuit) runDue(ctx context.Context, now time.Time) {
	if !now.Before(c.helloAt) {
		c.transmit(ctx, now)
	}
}

// nextDeadline is when the Circuit next has work to do.
func (c *Circuit) nextDeadline() time.Time { return c.helloAt }

// shutdown closes the Transport. With farewell set it first sends one
// last hello, which advertises the three way state Down.
func (c *Circuit) shutdown(ctx context.Context, farewell bool) {
	if farewell {
		c.transmit(ctx, time.Now())
	}

	if err := c.t.Close(); err != nil {
		c.log.Debug("failed to close transport", "err", err)
	}
}

// transmit sends one hello and schedules the next. Write failures are
// reported and dropped: a lost hello costs a hello interval, and a dead
// Transport surfaces through the reader.
func (c *Circuit) transmit(ctx context.Context, now time.Time) {
	c.helloAt = now.Add(jittered(c.cfg.HelloInterval))

	b, err := c.appendPointToPointHello(c.wb[:0])
	if err != nil {
		c.log.Error("failed to build hello", "err", err)
		return
	}

	c.wb = b

	// RFC 5309 section 4.1 recommends AllISs for a point to point Circuit
	// over a LAN.
	dst := AllISs()
	err = c.t.WritePDU(dst, b)
	c.tap(PDUEvent{
		Direction: DirectionSent,
		SNPA:      dst,
		Header: Header{
			Type:            PDUPointToPointHello,
			LengthIndicator: uint8(PDUPointToPointHello.fixedHeaderLen()),
		},
		Raw: b,
		Err: err,
	})

	if err != nil && c.log.Enabled(ctx, slog.LevelDebug) {
		c.log.Debug("failed to write hello", "err", err)
	}
}

// appendPointToPointHello encodes the Circuit's hello onto b, with the
// three way adjacency TLV for this hello in its last slot.
func (c *Circuit) appendPointToPointHello(b []byte) ([]byte, error) {
	threeWay, err := ThreeWayAdjacencyTLV(c.threeWayAdjacency())
	if err != nil {
		return nil, err
	}

	c.hello.TLVs[len(c.hello.TLVs)-1] = threeWay
	return c.hello.AppendBinary(b)
}

// threeWayAdjacency is the three way adjacency TLV's value for the next
// hello. A Circuit holding no adjacency advertises Down with its own
// extended local circuit ID and names no neighbor.
func (c *Circuit) threeWayAdjacency() ThreeWayAdjacency {
	return ThreeWayAdjacency{
		State:                  ThreeWayDown,
		ExtendedLocalCircuitID: c.cfg.ExtendedLocalCircuitID,
	}
}

// holdingTime is what this Circuit's hellos advertise: the hello interval
// times the multiplier, rounded up to the whole seconds the wire carries
// and clamped to its 16 bits, as FRR clamps its own.
func (c *Circuit) holdingTime() time.Duration {
	d := time.Duration(c.cfg.HoldingMultiplier) * c.cfg.HelloInterval
	s := (d + time.Second - 1) / time.Second
	return time.Duration(min(max(s, 1), math.MaxUint16)) * time.Second
}

// tap reports one PDU crossing the Circuit to the caller.
func (c *Circuit) tap(e PDUEvent) {
	if h := c.cfg.OnPDU; h != nil {
		h(c, e)
	}
}

// jittered scales d by a random factor in [0.75, 1.0), the jitter ISO
// 10589 clause 10.1 applies to every periodic timer so systems do not
// synchronize.
func jittered(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.75 + 0.25*rand.Float64()))
}
