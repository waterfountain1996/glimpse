package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"slices"
	"testing"

	"golang.org/x/net/proxy"
)

func testListener(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer t.Cleanup(func() { ln.Close() })

	return ln
}

func TestServer_Serve(t *testing.T) {
	var (
		srv       = newServer()
		proxyLn   = testListener(t)
		remoteLn  = testListener(t)
		done      = make(chan error, 1)
		remoteBuf bytes.Buffer
	)
	defer close(done)

	// Start the proxy.
	go func() {
		if err := srv.Serve(proxyLn); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("Serve(): %v", err)
		}
	}()

	go func() {
		err := func() error {
			c, err := remoteLn.Accept()
			if err != nil {
				return err
			}
			defer c.Close()

			var buf [64]byte
			n, err := c.Read(buf[:])
			if err != nil {
				return fmt.Errorf("Read(): %w", err)
			}

			_, _ = remoteBuf.Write(buf[:n])

			if _, err := c.Write(buf[:n]); err != nil {
				return fmt.Errorf("Write(): %w", err)
			}
			return nil
		}()
		done <- err
	}()

	dialer, err := proxy.SOCKS5("tcp", proxyLn.Addr().String(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	c, err := dialer.Dial("tcp", remoteLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })

	message := []byte("Hello, World!")

	if _, err := c.Write(message); err != nil {
		t.Fatalf("local: %v", err)
	}

	var buf [64]byte
	n, err := c.Read(buf[:])
	if err != nil {
		t.Fatalf("local: Read(): %v", err)
	}

	if !slices.Equal(message, buf[:n]) {
		t.Fatalf("local: slices are different:\nwant: %v\nhave: %v\n", message, buf[:n])
	}

	if b := remoteBuf.Bytes(); !slices.Equal(message, b) {
		t.Fatalf("remote: slices are different:\nwant: %v\nhave: %v\n", message, b)
	}

	if err := <-done; err != nil {
		t.Fatalf("remote: %v", err)
	}
}
