package glimpse

import (
	"bufio"
	"fmt"
	"io"
)

func readAuthMethods(r *bufio.Reader) ([]byte, error) {
	ver, err := r.ReadByte()
	if err != nil {
		return nil, err
	} else if ver != protoVersion {
		return nil, fmt.Errorf("%w: %#02X", errInvalidVersion, ver)
	}

	nmethods, err := r.ReadByte()
	if err != nil {
		return nil, err
	} else if nmethods == 0 {
		return nil, nil
	}

	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(r, methods); err != nil {
		return nil, err
	}
	return methods, nil
}

type Auth interface {
	Method() byte
	Negotiate(r *bufio.Reader, w io.Writer) (ok bool, err error)
}

type noAuth struct{}

func NoAuth() Auth                                              { return noAuth{} }
func (noAuth) Method() byte                                     { return 0x00 }
func (noAuth) Negotiate(*bufio.Reader, io.Writer) (bool, error) { return true, nil }
