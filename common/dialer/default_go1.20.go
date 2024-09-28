//go:build go1.20

package dialer

import (
	"net"

	"github.com/metacubex/tfo-go"
)

type tcpDialer = ExtendedTCPDialer

func newTCPDialer(dialer net.Dialer, tfoEnabled bool, tlsFragment *TLSFragment) (tcpDialer, error) {
	return tcpDialer{Dialer: dialer, DisableTFO: !tfoEnabled, TLSFragment: tlsFragment}, nil
}
