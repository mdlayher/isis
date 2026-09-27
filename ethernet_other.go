//go:build !linux

package isis

import (
	"errors"
	"fmt"
	"net"
	"runtime"
)

// errEthernetUnsupported is what every EthernetTransport method reports
// off Linux. It wraps errors.ErrUnsupported.
var errEthernetUnsupported = fmt.Errorf("isis: an Ethernet transport needs a Linux packet socket, which %s does not have: %w", runtime.GOOS, errors.ErrUnsupported)

// An EthernetTransport is a Transport over one Ethernet interface. It is
// implemented on Linux only, where its documentation lives; here every
// method reports that.
type EthernetTransport struct{}

var _ Transport = (*EthernetTransport)(nil)

// ListenEthernet is not implemented on this platform. It returns an error
// which wraps errors.ErrUnsupported.
func ListenEthernet(_ *net.Interface, _ *EthernetConfig) (*EthernetTransport, error) {
	return nil, errEthernetUnsupported
}

// ReadPDU implements Transport.
func (e *EthernetTransport) ReadPDU(_ []byte) (int, SNPA, error) {
	return 0, SNPA{}, errEthernetUnsupported
}

// WritePDU implements Transport.
func (e *EthernetTransport) WritePDU(_ SNPA, _ []byte) error { return errEthernetUnsupported }

// MaxPDULen implements Transport.
func (e *EthernetTransport) MaxPDULen() int { return 0 }

// LocalSNPA implements Transport.
func (e *EthernetTransport) LocalSNPA() SNPA { return SNPA{} }

// Close implements Transport.
func (e *EthernetTransport) Close() error { return errEthernetUnsupported }

// Groups reports the link layer multicast destinations this
// EthernetTransport joined, which off Linux is none.
func (e *EthernetTransport) Groups() []SNPA { return nil }
