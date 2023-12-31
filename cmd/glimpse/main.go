package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/waterfountain1996/glimpse/internal/glimpse"
	"github.com/waterfountain1996/glimpse/internal/socks"
)

func proxy(r io.Reader, w io.Writer) error {
	b := make([]byte, 4096)
	_, err := io.CopyBuffer(w, r, b)
	return err
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
		return fmt.Errorf("Invalid SOCKS version: %v", b)
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

func handleRequest(conn net.Conn, req *glimpse.Request) {
	log.Printf("Handling %v", req.String())

	if req.Cmd != socks.CmdConnect {
		err := glimpse.SendErrorReply(conn, socks.ReplyCmdNotSupported)
		if err != nil {
			log.Printf("error sending reply: %v", err)
		}

		conn.Close()
	}

	remote, err := net.Dial("tcp", req.AddrPort())
	if err != nil {
		log.Printf("Failed to connect to remove addr: %v", err)
		conn.Close()
	}
	defer remote.Close()

	log.Printf("Connected to %v", remote.RemoteAddr().String())

	addrPort, _ := netip.ParseAddrPort(remote.LocalAddr().String())
	err = glimpse.SendReply(conn, socks.ReplySuccess, addrPort)
	if err != nil {
		log.Printf("Error writing response: %v", err)
		conn.Close()
		return
	}

	errCh := make(chan error)
	go func() { errCh <- proxy(bufio.NewReader(conn), remote) }()
	go func() { errCh <- proxy(bufio.NewReader(remote), conn) }()

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

	req, err := glimpse.ReadRequest(conn)
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
