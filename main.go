package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

const programName = "glimpse"

func main() {
	ctx := context.Background()
	code, err := run(ctx, os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", programName, err)
	}
	os.Exit(code)
}

func run(ctx context.Context, args []string) (int, error) {
	flag.CommandLine.Init(programName, flag.ContinueOnError)
	var (
		bindFlag   = flag.String("b", ":1080", "Address to listen on")
		userFlag   = flag.String("u", "", "Proxy user")
		passwdFlag = flag.String("p", "", "Proxy password")
	)
	if err := flag.CommandLine.Parse(args); err != nil {
		code := 2
		if errors.Is(err, flag.ErrHelp) {
			code = 0
		}
		return code, nil
	}

	// Username without a password is invalid configuration, but password without a username is.
	if *userFlag != "" && *passwdFlag == "" {
		return 2, errors.New("password must not be empty when -u is used")
	}

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", *bindFlag)
	if err != nil {
		return 1, err
	}
	defer ln.Close()

	var opts []serverOpt
	if *userFlag != "" || *passwdFlag != "" {
		opts = append(opts, withPasswordAuth(*userFlag, *passwdFlag))
	}

	var (
		srv   = newServer(opts...)
		errCh = make(chan error, 1)
	)

	go func() {
		log.Printf("Listening on %s\n", ln.Addr())
		if err := srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		return 1, err
	}

	log.Println("Shutting down...")

	return 0, nil
}
