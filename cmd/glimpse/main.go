package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/waterfountain1996/glimpse"
)

func main() {
	ln, err := net.Listen("tcp", ":1080")
	if err != nil {
		fmt.Fprintf(os.Stderr, "glimpse: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()

	srv := glimpse.NewServer()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Fprintf(os.Stderr, "glimpse: %v\n", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
}
