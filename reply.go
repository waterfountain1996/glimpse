package glimpse

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
)

type socksError uint8

const (
	errGeneralFailure          = socksError(0x01)
	errConnectionNotAllowed    = socksError(0x02)
	errNetworkUnreachable      = socksError(0x03)
	errHostUnreachable         = socksError(0x04)
	errConnectionRefused       = socksError(0x05)
	errTTLExpired              = socksError(0x06)
	errCommandNotSupported     = socksError(0x07)
	errAddressTypeNotSupported = socksError(0x08)
)

func (e socksError) Error() string {
	return fmt.Sprintf("SOCKS5 error (%#02X)", e)
}

type reply struct {
	status  uint8
	bndAddr netip.AddrPort
}

func replyFromConn(nc net.Conn) *reply {
	return &reply{
		status:  0x00,
		bndAddr: netip.MustParseAddrPort(nc.LocalAddr().String()),
	}
}

func replyFromError(err socksError) *reply {
	return &reply{
		status:  uint8(err),
		bndAddr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 0),
	}
}

func writeReply(w io.Writer, r *reply) error {
	var buf bytes.Buffer
	buf.WriteByte(protoVersion)
	buf.WriteByte(r.status)
	buf.WriteByte(0x00) // Unused reserved byte

	atyp := atypIPv4
	if r.bndAddr.Addr().Is6() {
		atyp = atypIPv6
	}
	buf.WriteByte(atyp)

	buf.Write(r.bndAddr.Addr().AsSlice())
	binary.Write(&buf, binary.BigEndian, r.bndAddr.Port())

	_, err := buf.WriteTo(w)
	return err
}
