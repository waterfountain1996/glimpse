package glimpse

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"

	"github.com/waterfountain1996/glimpse/internal/socks"
)

// SOCKS5 request payload
type Request struct {
	Cmd     socks.Cmd
	Atyp    socks.Atyp
	dstAddr string
	dstPort uint16
}

// Return a human-readable representation of a request
func (r *Request) String() string {
	var cmdString string
	switch r.Cmd {
	case socks.CmdConnect:
		cmdString = "CONNECT"
	case socks.CmdBind:
		cmdString = "BIND"
	case socks.CmdUDPAssociate:
		cmdString = "UDP ASSOCIATE"
	}
	return fmt.Sprintf("%v to %v", cmdString, r.AddrPort())
}

// Return an address string that can be passed to net.Dial()
func (r *Request) AddrPort() string {
	return fmt.Sprintf("%v:%v", r.dstAddr, r.dstPort)
}

// Read and parse a SOCKS5 request from a socket
func ReadRequest(conn net.Conn) (*Request, error) {
	r := bufio.NewReader(conn)

	b := make([]byte, 4)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}

	ver, cmd, atyp := b[0], socks.Cmd(b[1]), socks.Atyp(b[3])
	if ver != socks.Version {
		err := SendErrorReply(conn, socks.ReplyError)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("Invalid SOCKS5 version: %v", ver)
	}

	switch cmd {
	case socks.CmdConnect:
		fallthrough
	case socks.CmdBind:
		fallthrough
	case socks.CmdUDPAssociate:
	default:
		err := SendErrorReply(conn, socks.ReplyCmdNotSupported)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("Unsupported SOCKS5 command: %v", cmd)
	}

	var dstAddr string

	switch atyp {
	case socks.AtypIP4:
		fallthrough
	case socks.AtypIP6:
		b := slices.Grow(b, int(atyp*4))
		_, err := io.ReadFull(r, b)
		if err != nil {
			return nil, err
		}

		addr, _ := netip.AddrFromSlice(b)
		dstAddr = addr.String()
	case socks.AtypDomain:
		length, err := r.ReadByte()
		if err != nil {
			return nil, err
		}

		b = make([]byte, length)
		_, err = io.ReadFull(r, b)
		if err != nil {
			return nil, err
		}

		dstAddr = string(b)
	default:
		err := SendErrorReply(conn, socks.ReplyAtypNotSupported)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("Unsupported address type: %v", atyp)
	}

	b = make([]byte, 2)
	_, err = io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}

	dstPort := binary.BigEndian.Uint16(b)

	return &Request{
		Cmd:     cmd,
		Atyp:    atyp,
		dstAddr: dstAddr,
		dstPort: dstPort,
	}, nil
}
