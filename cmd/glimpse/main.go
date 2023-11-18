package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

const SocksProtoVersion uint8 = 5

type SocksAuth uint8

const (
	SocksAuthNone     SocksAuth = 0
	SocksAuthGssapi   SocksAuth = 1
	SocksAuthPassword SocksAuth = 2
	SocksAuthInvalid  SocksAuth = 0xFF
)

type SocksCmd uint8

const (
	SocksCmdConnect      SocksCmd = 1
	SocksCmdBind         SocksCmd = 2
	SocksCmdUDPAssociate SocksCmd = 3
)

type SocksAtyp uint8

const (
	SocksAtypIP4    SocksAtyp = 1
	SocksAtypDomain SocksAtyp = 3
	SocksAtypIP6    SocksAtyp = 4
)

type SocksReply uint8

const (
	SocksReplySuccess          SocksReply = 0
	SocksReplyError            SocksReply = 1
	SocksReplyForbidden        SocksReply = 2
	SocksReplyNetUnreachable   SocksReply = 3
	SocksReplyHostUnreachable  SocksReply = 4
	SocksReplyRefused          SocksReply = 5
	SocksReplyExpired          SocksReply = 6
	SocksReplyCmdNotSupported  SocksReply = 7
	SocksReplyAtypNotSupported SocksReply = 8
)

var PayloadTooShort = errors.New("Payload too short")

type SocksRequest struct {
	cmd     SocksCmd
	atyp    SocksAtyp
	dstAddr string
	dstPort uint16
}

func (r *SocksRequest) String() string {
	var cmdString string
	switch r.cmd {
	case SocksCmdConnect:
		cmdString = "CONNECT"
	case SocksCmdBind:
		cmdString = "BIND"
	case SocksCmdUDPAssociate:
		cmdString = "UDP ASSOCIATE"
	}
	return fmt.Sprintf("%v to %v:%v", cmdString, r.dstAddr, r.dstPort)
}

type SocksResponse struct {
	reply   SocksReply
	atyp    SocksAtyp
	bndAddr string
	bndPort uint16
}

func (r *SocksResponse) AsSlice() []byte {
	addr, _ := netip.ParseAddr(r.bndAddr)
	slice := []byte{
		SocksProtoVersion,
		byte(r.reply),
		0x0, // RSV
		byte(r.atyp),
	}
	slice = append(slice, addr.AsSlice()...)
	slice = binary.BigEndian.AppendUint16(slice, r.bndPort)
	return slice
}

func NewErrorResponse(reply SocksReply) *SocksResponse {
	return &SocksResponse{
		reply:   reply,
		atyp:    SocksAtypIP4,
		bndAddr: "0.0.0.0",
		bndPort: 0,
	}
}

func WithTimeout(f func() error, timeout time.Duration) error {
	result := make(chan error, 1)

	go func() {
		result <- f()
	}()

	select {
	case err := <-result:
		return err
	case <-time.After(timeout):
		return errors.New("Timeout")
	}
}

func handleAuth(conn net.Conn, methods []SocksAuth) error {
	r := bufio.NewReader(conn)

	// Read protocol version
	b, err := r.ReadByte()
	if err != nil {
		return err
	} else if b != SocksProtoVersion {
		return errors.New(fmt.Sprintf("Invalid SOCKS version: %v", b))
	}

	// Read number of auth methods
	numMethods, err := r.ReadByte()
	if err != nil {
		return err
	} else if numMethods == 0 {
		return errors.New("No auth methods are available")
	}

	clientMethods := make([]byte, numMethods)
	duration, _ := time.ParseDuration("1s")

	// We read exactly `numMethods` bytes with a 1 second timeout
	err = WithTimeout(func() error {
		_, err = io.ReadFull(r, clientMethods)
		return err
	}, duration)
	if err != nil {
		return err
	}

	selectedMethod := SocksAuthInvalid
	for _, rawMethod := range clientMethods {
		method := SocksAuth(rawMethod)
		if slices.Contains(methods, method) {
			selectedMethod = SocksAuth(method)
			break
		}
	}

	_, err = conn.Write([]byte{SocksProtoVersion, byte(selectedMethod)})
	if err != nil {
		return err
	}

	if selectedMethod == SocksAuthInvalid {
		conn.Close()
	}

	return nil
}

func readRequest(conn net.Conn) (*SocksRequest, error) {
	r := bufio.NewReader(conn)

	b := make([]byte, 4)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}

	ver, cmd, atyp := b[0], SocksCmd(b[1]), SocksAtyp(b[3])
	if ver != SocksProtoVersion {
		return nil, errors.New(fmt.Sprintf("Invalid SOCKS version: %v", b))
	}

	var dstAddr string

	switch atyp {
	case SocksAtypIP4:
		fallthrough
	case SocksAtypIP6:
		b = slices.Grow(b, int(atyp * 4))
		_, err := io.ReadFull(r, b)
		if err != nil {
			return nil, err
		}
		addr, _ := netip.AddrFromSlice(b)
		dstAddr = addr.String()
	case SocksAtypDomain:
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
		return nil, errors.New(fmt.Sprintf("Unsupported address type: %v", atyp))
	}

	b = make([]byte, 2)
	_, err = io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}
	dstPort := binary.BigEndian.Uint16(b)

	return &SocksRequest{
		cmd: cmd,
		atyp: atyp,
		dstAddr: dstAddr,
		dstPort: dstPort,
	}, nil
}

func handleRequest(conn net.Conn, req *SocksRequest) {
	log.Printf("Handling %v", req.String())
	var res SocksResponse

	if req.cmd != SocksCmdConnect {
		log.Printf("Here")
		res = *NewErrorResponse(SocksReplyCmdNotSupported)
		conn.Write(res.AsSlice())
		conn.Close()
	}

	remote, err := net.Dial("tcp", fmt.Sprintf("%v:%v", req.dstAddr, req.dstPort))
	if err != nil {
		log.Printf("Failed to connect to remove addr: %v", err)
		conn.Close()
	}

	log.Printf("Connected to %v", remote.RemoteAddr().String())

	addrPort, _ := netip.ParseAddrPort(remote.LocalAddr().String())

	res = SocksResponse{
		reply: SocksReplySuccess,
		atyp: SocksAtypIP4,
		bndAddr: addrPort.Addr().String(),
		bndPort: addrPort.Port(),
	}
	_, err = conn.Write(res.AsSlice())
	if err != nil {
		log.Printf("Error writing response: %v", err)
		conn.Close()
		return
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		r := bufio.NewReader(remote)
		w := bufio.NewWriter(conn)
		for {
			_, err := r.WriteTo(w)
			if err != nil {
				log.Printf("proxy error: %v", err)
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(remote)
		for {
			_, err := r.WriteTo(w)
			if err != nil {
				log.Printf("proxy error: %v", err)
				return
			}
		}
	}()

	wg.Wait()
}

func handleConnection(conn net.Conn) {
	err := handleAuth(conn, []SocksAuth{SocksAuthNone})
	if err != nil {
		log.Printf("Failed to handle auth: %v", err)
		conn.Close()
		return
	}

	req, err := readRequest(conn)
	if err != nil {
		log.Printf("Failed to handle request: %v", err)
		conn.Close()
		return
	}

	handleRequest(conn, req)
}

func main() {
	ln, err := net.Listen("tcp", ":1080")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Listening on %v...", ln.Addr().String())

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go handleConnection(conn)
	}
}
