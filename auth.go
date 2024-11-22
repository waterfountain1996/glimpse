package main

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"io"
)

type authenticator interface {
	Method() byte

	Authenticate(r *bufio.Reader, w io.Writer) (ok bool, err error)
}

type invalidAuth struct{}

func (invalidAuth) Method() byte                                            { return 0xFF }
func (invalidAuth) Authenticate(_ *bufio.Reader, _ io.Writer) (bool, error) { return false, nil }

var _ authenticator = (*invalidAuth)(nil)

type noAuth struct{}

func (noAuth) Method() byte                                            { return 0x00 }
func (noAuth) Authenticate(_ *bufio.Reader, _ io.Writer) (bool, error) { return true, nil }

var _ authenticator = (*noAuth)(nil)

type passwordAuth struct {
	Username string
	Password string
}

func (passwordAuth) Method() byte { return 0x02 }

func (a *passwordAuth) Authenticate(r *bufio.Reader, w io.Writer) (bool, error) {
	ver, err := r.ReadByte()
	if err != nil {
		return false, err
	} else if ver != 0x01 {
		return false, fmt.Errorf("invalid password auth version: %d", ver)
	}

	uname, err := readVariable(r)
	if err != nil {
		return false, err
	}

	passwd, err := readVariable(r)
	if err != nil {
		return false, err
	}

	ok := a.verify(uname, passwd)

	status := byte(0x00)
	if !ok {
		status = 0x01
	}
	buf := [2]byte{0x01, status}
	if _, err := w.Write(buf[:]); err != nil {
		return false, err
	}
	return ok, nil
}

func (a *passwordAuth) verify(username, passwd []byte) bool {
	ok1 := subtle.ConstantTimeCompare([]byte(a.Username), username) == 1
	ok2 := subtle.ConstantTimeCompare([]byte(a.Password), passwd) == 1
	return ok1 && ok2
}

var _ authenticator = (*passwordAuth)(nil)
