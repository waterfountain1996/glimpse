package glimpse

import (
	"encoding/binary"
	"net"
	"net/netip"

	"github.com/waterfountain1996/glimpse/internal/socks"
)

// Send reply to a client
func SendReply(conn net.Conn, r socks.Reply, bndAddr netip.AddrPort) error {
	atyp := socks.AtypIP4
	if bndAddr.Addr().Is6() {
		atyp = socks.AtypIP6
	}

	b := []byte{socks.Version, byte(r), 0, byte(atyp)}
	b = append(b, bndAddr.Addr().AsSlice()...)
	b = binary.BigEndian.AppendUint16(b, bndAddr.Port())

	_, err := conn.Write(b)
	return err
}

// Send error reply to a client with address and port both set to 0
func SendErrorReply(conn net.Conn, r socks.Reply) error {
	addr, _ := netip.ParseAddrPort("0.0.0.0:0")
	return SendReply(conn, r, addr)
}
