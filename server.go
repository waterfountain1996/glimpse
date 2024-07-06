package glimpse

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	dialTimeout = 3 * time.Second
)

type conn struct {
	r  *bufio.Reader
	wc io.WriteCloser
}

func newConn(nc net.Conn) *conn {
	return &conn{
		r:  bufio.NewReader(nc),
		wc: nc,
	}
}

func (c *conn) close() error {
	return c.wc.Close()
}

type Server struct{}

func NewServer() *Server {
	return &Server{}
}

func (s *Server) Serve(ln net.Listener) error {
	for {
		nc, err := ln.Accept()
		if err != nil {
			return err
		}

		c := newConn(nc)
		go func() {
			if err := s.handleConnection(c); err != nil {
				log.Println(err)
			}
		}()
	}
}

func (s *Server) handleConnection(c *conn) error {
	defer c.close()

	ok, err := negotiateAuth(c, NoAuth()) // TODO: Configure auth methods as server options
	if !ok {
		return err
	}

	req, err := readRequest(c.r)
	if err != nil {
		return fmt.Errorf("error reading request: %w", err)
	}

	// We only allow CONNECT requests
	if req.cmd != cmdConnect {
		return writeReply(c.wc, replyFromError(errCommandNotSupported))
	}

	rc, err := net.DialTimeout("tcp", req.DialAddr(), dialTimeout)
	if err != nil {
		switch {
		case isConnectionRefusedError(err):
			return writeReply(c.wc, replyFromError(errConnectionRefused))
		case isTimeoutError(err):
			return writeReply(c.wc, replyFromError(errTTLExpired))
		}
		return fmt.Errorf("error dialing remote host: %w", err)
	}
	defer rc.Close()

	if err := writeReply(c.wc, replyFromConn(rc)); err != nil {
		return fmt.Errorf("error writing reply: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go io.Copy(rc, c.r)
	go io.Copy(c.wc, rc)

	wg.Wait()
	return nil
}

func negotiateAuth(c *conn, auth ...Auth) (bool, error) {
	methods, err := readAuthMethods(c.r)
	if err != nil {
		return false, err
	}

	for _, a := range auth {
		if slices.Contains(methods, a.Method()) {
			if _, err := c.wc.Write([]byte{protoVersion, a.Method()}); err != nil {
				return false, err
			}
			return a.Negotiate(c.r, c.wc)
		}
	}
	return false, nil
}

func isConnectionRefusedError(err error) bool {
	return strings.Contains(err.Error(), "connection refused")
}

func isTimeoutError(err error) bool {
	netError, ok := err.(net.Error)
	return ok && netError.Timeout()
}
