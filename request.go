package glimpse

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
)

var errInvalidRequest = errors.New("invalid SOCKS5 request")

type request struct {
	cmd     byte
	atyp    byte
	dstAddr string
	dstPort uint16
}

func (r request) DialAddr() string {
	return net.JoinHostPort(r.dstAddr, strconv.FormatUint(uint64(r.dstPort), 10))
}

func (r request) String() string {
	cmd := "-"
	switch r.cmd {
	case cmdConnect:
		cmd = "CONNECT"
	case cmdBind:
		cmd = "BIND"
	case cmdUdpAssociate:
		cmd = "UDP ASSOCIATE"
	}
	return fmt.Sprintf("%s -> %s", cmd, r.DialAddr())
}

func readRequest(r *bufio.Reader) (*request, error) {
	ver, err := r.ReadByte()
	if err != nil {
		return nil, err
	} else if ver != protoVersion {
		return nil, fmt.Errorf("%w: %#02X", errInvalidVersion, ver)
	}

	var req request

	req.cmd, err = r.ReadByte()
	if err != nil {
		return nil, err
	}
	switch req.cmd {
	case cmdConnect, cmdBind, cmdUdpAssociate:
	default:
		return nil, fmt.Errorf("%w: unknown command: %#02X", errInvalidRequest, req.cmd)
	}

	// Skip unused reserved byte
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}

	req.atyp, err = r.ReadByte()
	if err != nil {
		return nil, err
	}
	switch req.atyp {
	case atypIPv4, atypIPv6:
		addrLen := req.atyp * 4
		buf := make([]byte, addrLen+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}

		addr, _ := netip.AddrFromSlice(buf[:addrLen])
		req.dstAddr = addr.String()
		req.dstPort = binary.BigEndian.Uint16(buf[addrLen:])
	case atypDomainName:
		addrLen, err := r.ReadByte()
		if err != nil {
			return nil, err
		}

		buf := make([]byte, addrLen+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}

		req.dstAddr = string(buf[:addrLen])
		req.dstPort = binary.BigEndian.Uint16(buf[addrLen:])
	default:
		return nil, fmt.Errorf("%w: unknown address type: %#02X", errInvalidRequest, req.atyp)
	}

	return &req, nil
}
