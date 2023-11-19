package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/waterfountain1996/glimpse/internal/socks"
)

type SocksRequest struct {
	cmd     socks.Cmd
	atyp    socks.Atyp
	dstAddr string
	dstPort uint16
}

func (r *SocksRequest) String() string {
	var cmdString string
	switch r.cmd {
	case socks.CmdConnect:
		cmdString = "CONNECT"
	case socks.CmdBind:
		cmdString = "BIND"
	case socks.CmdUDPAssociate:
		cmdString = "UDP ASSOCIATE"
	}
	return fmt.Sprintf("%v to %v:%v", cmdString, r.dstAddr, r.dstPort)
}

type SocksResponse struct {
	reply   socks.Reply
	atyp    socks.Atyp
	bndAddr string
	bndPort uint16
}

func (r *SocksResponse) AsSlice() []byte {
	addr, _ := netip.ParseAddr(r.bndAddr)
	slice := []byte{
		socks.Version,
		byte(r.reply),
		0x0, // RSV
		byte(r.atyp),
	}
	slice = append(slice, addr.AsSlice()...)
	slice = binary.BigEndian.AppendUint16(slice, r.bndPort)
	return slice
}

func NewErrorResponse(reply socks.Reply) *SocksResponse {
	return &SocksResponse{
		reply:   reply,
		atyp:    socks.AtypIP4,
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

func handleAuth(conn net.Conn, methods []socks.AuthMethod) error {
	r := bufio.NewReader(conn)

	// Read protocol version
	b, err := r.ReadByte()
	if err != nil {
		return err
	} else if b != socks.Version {
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

	selectedMethod := socks.AuthInvalid
	for _, rawMethod := range clientMethods {
		method := socks.AuthMethod(rawMethod)
		if slices.Contains(methods, method) {
			selectedMethod = method
			break
		}
	}

	_, err = conn.Write([]byte{socks.Version, byte(selectedMethod)})
	if err != nil {
		return err
	}

	if selectedMethod == socks.AuthInvalid {
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

	ver, cmd, atyp := b[0], socks.Cmd(b[1]), socks.Atyp(b[3])
	if ver != socks.Version {
		return nil, errors.New(fmt.Sprintf("Invalid SOCKS version: %v", b))
	}

	var dstAddr string

	switch atyp {
	case socks.AtypIP4:
		fallthrough
	case socks.AtypIP6:
		b = slices.Grow(b, int(atyp*4))
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
		return nil, errors.New(fmt.Sprintf("Unsupported address type: %v", atyp))
	}

	b = make([]byte, 2)
	_, err = io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}
	dstPort := binary.BigEndian.Uint16(b)

	return &SocksRequest{
		cmd:     cmd,
		atyp:    atyp,
		dstAddr: dstAddr,
		dstPort: dstPort,
	}, nil
}

func handleRequest(conn net.Conn, req *SocksRequest) {
	log.Printf("Handling %v", req.String())
	var res SocksResponse

	if req.cmd != socks.CmdConnect {
		log.Printf("Here")
		res = *NewErrorResponse(socks.ReplyCmdNotSupported)
		conn.Write(res.AsSlice())
		conn.Close()
	}

	remote, err := net.Dial("tcp", fmt.Sprintf("%v:%v", req.dstAddr, req.dstPort))
	if err != nil {
		log.Printf("Failed to connect to remove addr: %v", err)
		conn.Close()
	}
	defer remote.Close()

	log.Printf("Connected to %v", remote.RemoteAddr().String())

	addrPort, _ := netip.ParseAddrPort(remote.LocalAddr().String())

	res = SocksResponse{
		reply:   socks.ReplySuccess,
		atyp:    socks.AtypIP4,
		bndAddr: addrPort.Addr().String(),
		bndPort: addrPort.Port(),
	}
	_, err = conn.Write(res.AsSlice())
	if err != nil {
		log.Printf("Error writing response: %v", err)
		conn.Close()
		return
	}

	errCh := make(chan error)

	go func() {
		r := bufio.NewReader(conn)
		b := make([]byte, 4096)
		_, err := io.CopyBuffer(remote, r, b)
		if err != nil {
			errCh <- err
		}
	}()

	go func() {
		r := bufio.NewReader(remote)
		b := make([]byte, 4096)
		_, err := io.CopyBuffer(conn, r, b)
		if err != nil {
			errCh <- err
		}
	}()

	for i := 0; i < 2; i++ {
		err := <-errCh
		if err != nil {
			log.Printf("proxy error: %v", err)
			break
		}
	}

	log.Printf("%v finished", req)
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	err := handleAuth(conn, []socks.AuthMethod{socks.AuthNone})
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
	var bindAddr string
	flag.StringVar(&bindAddr, "b", ":1080", "Address to bind to")

	flag.Parse()

	ln, err := net.Listen("tcp", bindAddr)
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
