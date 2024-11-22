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
	// Client authentication timeout.
	authTimeout = 10 * time.Second

	// Remote host dial timeout.
	dialTimeout = 5 * time.Second

	// Size of buffers used in io.CopyBuffer.
	copyBufSize = 4096
)

type serverOpt func(s *server)

func withPasswordAuth(username, passwd string) serverOpt {
	return func(s *server) {
		s.auth = append(s.auth, &passwordAuth{
			Username: username,
			Password: passwd,
		})
	}
}

type server struct {
	auth    []authenticator
	bufPool sync.Pool
}

func newServer(opts ...serverOpt) *server {
	srv := &server{
		bufPool: sync.Pool{
			New: func() any {
				return make([]byte, copyBufSize)
			},
		},
	}
	for _, f := range opts {
		f(srv)
	}
	if len(srv.auth) == 0 {
		srv.auth = []authenticator{noAuth{}}
	}
	return srv
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

func (s *server) serveClient(nc net.Conn) error {
	defer nc.Close()

	r := bufio.NewReader(nc)

	_ = nc.SetDeadline(time.Now().Add(authTimeout))

	methods, err := readMethodSelection(r)
	if err != nil {
		return fmt.Errorf("error reading method selection message: %w", err)
	}

	ok, err := s.authenticateClient(r, nc, methods)
	if err != nil {
		return fmt.Errorf("auth sub-negotiation error: %w", err)
	} else if !ok {
		return errors.New("unauthorized")
	}

	cmd, dialAddr, err := readRequest(r)
	if err != nil {
		return fmt.Errorf("error reading request: %w", err)
	} else if cmd != cmdConnect {
		return writeReply(nc, repCmdNotSupported, zeroAddr)
	}

	// Reset the timeout.
	_ = nc.SetDeadline(time.Time{})

	if err := s.handleConnect(unbufferConnReader(nc, r), dialAddr); err != nil {
		return err
	}
	return nil
}

func (s *server) authenticateClient(r *bufio.Reader, w io.Writer, methods []byte) (bool, error) {
	var am authenticator = invalidAuth{}
	for _, auth := range s.auth {
		if slices.Contains(methods, auth.Method()) {
			am = auth
			break
		}
	}

	if err := writeAuthMethod(w, am.Method()); err != nil {
		return false, err
	}

	return am.Authenticate(r, w)
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
