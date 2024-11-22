package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"
)

var zeroAddr = netip.AddrPortFrom(netip.IPv4Unspecified(), 0)

var errInvalidRequest = errors.New("invalid request")

const (
	// Remote host dial timeout.
	dialTimeout = 5 * time.Second

	// Size of buffers used in io.CopyBuffer.
	copyBufSize = 4096
)

type server struct {
	bufPool sync.Pool
}

func newServer() *server {
	return &server{
		bufPool: sync.Pool{
			New: func() any {
				return make([]byte, copyBufSize)
			},
		},
	}
}

func (s *server) Serve(ln net.Listener) error {
	defer ln.Close()

	for {
		nc, err := ln.Accept()
		if err != nil {
			// TODO: Maybe we can recover from this?
			return err
		}

		go func() {
			_ = s.serveClient(nc)
		}()
	}
}

// TODO: Add timeouts.
func (s *server) serveClient(nc net.Conn) error {
	defer nc.Close()

	r := bufio.NewReader(nc)

	methods, err := readMethodSelection(r)
	if err != nil {
		return fmt.Errorf("error reading method selection message: %w", err)
	}

	// TODO: Add password auth.
	am := methodNoAuth
	if !slices.Contains(methods, am) {
		am = methodInvalid
	}
	if err := writeAuthMethod(nc, am); err != nil {
		return fmt.Errorf("auth method selection: %w", err)
	} else if am == methodInvalid {
		return nil
	}

	cmd, dialAddr, err := readRequest(r)
	if err != nil {
		return fmt.Errorf("error reading request: %w", err)
	} else if cmd != cmdConnect {
		return writeReply(nc, repCmdNotSupported, zeroAddr)
	}

	if err := s.handleConnect(unbufferConnReader(nc, r), dialAddr); err != nil {
		return err
	}
	return nil
}

type connWrapper struct {
	net.Conn
	io.Reader
}

func unbufferConnReader(nc net.Conn, br *bufio.Reader) net.Conn {
	var r io.Reader = nc
	if n := br.Buffered(); n > 0 {
		p := make([]byte, n)
		_, _ = io.ReadFull(br, p)
		r = io.MultiReader(bytes.NewReader(p), nc)
	}
	return &connWrapper{
		Conn:   nc,
		Reader: r,
	}
}

func (cw *connWrapper) Read(p []byte) (int, error) {
	return cw.Reader.Read(p)
}

func (s *server) handleConnect(nc net.Conn, dialAddr string) error {
	remote, err := net.DialTimeout("tcp", dialAddr, dialTimeout)
	if err != nil {
		status := repFailure
		switch {
		case isTimeoutError(err):
			status = repTTLExpired
		case errors.Is(err, syscall.ECONNREFUSED):
			status = repRefused
		}
		return writeReply(nc, status, zeroAddr)
	}
	defer remote.Close()

	bndAddr := zeroAddr
	if addr := remote.LocalAddr(); addr != nil {
		// Better be safe than sorry.
		if ap, err := netip.ParseAddrPort(addr.String()); err != nil {
			bndAddr = ap
		}
	}
	if err := writeReply(nc, repSuccess, bndAddr); err != nil {
		return err
	}

	done := make(chan error, 2)
	defer close(done)

	go func() {
		defer nc.Close()

		buf := s.getBuffer()
		defer s.putBuffer(buf)

		_, err := io.CopyBuffer(nc, remote, buf)
		done <- err
	}()

	go func() {
		defer remote.Close()

		buf := s.getBuffer()
		defer s.putBuffer(buf)

		_, err := io.CopyBuffer(remote, nc, buf)
		done <- err
	}()

	for range 2 {
		<-done
	}
	return nil
}

func (s *server) getBuffer() []byte {
	return s.bufPool.Get().([]byte)
}

func (s *server) putBuffer(buf []byte) {
	s.bufPool.Put(buf)
}

func readMethodSelection(r *bufio.Reader) ([]byte, error) {
	ver, err := r.ReadByte()
	if err != nil {
		return nil, err
	} else if ver != protocolVersion {
		return nil, fmt.Errorf("%w: %d", errInvalidVersion, ver)
	}

	return readVariable(r)
}

func readVariable(r *bufio.Reader) ([]byte, error) {
	length, err := r.ReadByte()
	if err != nil {
		return nil, err
	} else if length == 0 {
		return nil, nil
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeAuthMethod(w io.Writer, method byte) error {
	b := [2]byte{protocolVersion, method}
	_, err := w.Write(b[:])
	return err
}

func readRequest(r *bufio.Reader) (cmd byte, dst string, err error) {
	ver, err := r.ReadByte()
	if err != nil {
		return 0, "", err
	} else if ver != protocolVersion {
		return 0, "", fmt.Errorf("%w: %d", errInvalidVersion, ver)
	}

	cmd, err = r.ReadByte()
	if err != nil {
		return 0, "", err
	}
	switch cmd {
	case cmdConnect, cmdBind, cmdUDPAssociate:
	default:
		return 0, "", fmt.Errorf("%w: invalid command: %d", errInvalidRequest, cmd)
	}

	// Skip 1 reserved byte.
	if _, err := r.Discard(1); err != nil {
		return 0, "", err
	}

	atyp, err := r.ReadByte()
	if err != nil {
		return 0, "", err
	}

	var dstAddr string
	switch atyp {
	case atypIPv4, atypIPv6:
		buf := make([]byte, atyp*4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, "", err
		}
		dstAddr = net.IP(buf).String()
	case atypFQDN:
		buf, err := readVariable(r)
		if err != nil {
			return 0, "", err
		}
		dstAddr = string(buf)
	default:
		return 0, "", fmt.Errorf("%w: invalid address type: %d", errInvalidRequest, atyp)
	}

	var dstPort uint16
	if err := binary.Read(r, binary.BigEndian, &dstPort); err != nil {
		return 0, "", err
	}

	dst = net.JoinHostPort(dstAddr, strconv.FormatUint(uint64(dstPort), 10))
	return cmd, dst, nil
}

func writeReply(w io.Writer, status byte, bndAddr netip.AddrPort) error {
	atyp := atypIPv4
	if bndAddr.Addr().Is6() {
		atyp = atypIPv6
	}

	buf := make([]byte, 4+4*atyp+2)
	buf[0] = protocolVersion
	buf[1] = status
	// buf[2] = 0x00 (reserved)
	buf[3] = atyp

	copy(buf[4:], bndAddr.Addr().AsSlice())
	binary.BigEndian.PutUint16(buf[4+4*atyp:], bndAddr.Port())

	_, err := w.Write(buf)
	return err
}

func isTimeoutError(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}
