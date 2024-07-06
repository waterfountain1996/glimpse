package glimpse

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"slices"
	"testing"
)

func TestReadAuthMethods_Success(t *testing.T) {
	tests := []struct {
		buf      []byte
		expected []byte
	}{
		{
			buf:      []byte{0x05, 0x00},
			expected: nil,
		},
		{
			buf:      []byte{0x05, 0x01, 0x00},
			expected: []byte{0x00},
		},
		{
			buf:      []byte{0x05, 0x02, 0x00, 0x02},
			expected: []byte{0x00, 0x02},
		},
		{
			buf:      []byte{0x05, 0x02, 0x00, 0x02, 0xDE, 0xAD, 0xBE, 0xEF},
			expected: []byte{0x00, 0x02},
		},
	}

	for _, tc := range tests {
		r := bufio.NewReader(bytes.NewReader(tc.buf))
		got, err := readAuthMethods(r)
		if err != nil {
			t.Fatal("unexpected error when reading auth methods:", err)
		}

		if !slices.Equal(got, tc.expected) {
			t.Fatalf("failed to read auth methods: want %v got %v", tc.expected, got)
		}
	}
}

func TestReadAuthMethods_ShortBuffer(t *testing.T) {
	buf := []byte{0x05, 0xFF, 0x00}
	r := bufio.NewReader(bytes.NewReader(buf))
	_, err := readAuthMethods(r)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf(
			"readAuthMethods() didn't fail on invalid request: want %v got %v",
			io.ErrUnexpectedEOF,
			err,
		)
	}
}

func TestReadAuthMethods_InvalidVersion(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{0xFF}))
	_, err := readAuthMethods(r)
	if !errors.Is(err, errInvalidVersion) {
		t.Fatalf("readAuthMethods() version check failed: want %v got %v", errInvalidVersion, err)
	}
}

func TestNoAuth(t *testing.T) {
	a := noAuth{}

	if m := a.Method(); m != 0x00 {
		t.Fatalf("invalid no auth method: want %#02X got %#02X", 0x00, m)
	}

	ok, err := a.Negotiate(nil, nil)
	if err != nil {
		t.Fatal("unexpected no auth negotiation error:", err)
	}

	if !ok {
		t.Fatal("unexpected no auth negotiation result")
	}
}
