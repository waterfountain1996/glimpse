package glimpse

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
)

var (
	localhost4  = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	localhost16 = netip.MustParseAddr("::1")
)

func TestWriteReply(t *testing.T) {
	tests := []struct {
		name string
		rep  reply
		atyp byte
	}{
		{
			name: "IPv4",
			rep: reply{
				status:  0x00,
				bndAddr: netip.AddrPortFrom(localhost4, 1337),
			},
			atyp: atypIPv4,
		},
		{
			name: "IPv6",
			rep: reply{
				status:  0x00,
				bndAddr: netip.AddrPortFrom(localhost16, 420),
			},
			atyp: atypIPv6,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := writeReply(&buf, &tc.rep)
			if err != nil {
				t.Fatalf("unexpected error when writing a reply: %v", err)
			}

			p := buf.Bytes()
			if p[0] != protoVersion {
				t.Fatalf("expected protocol version to be %#02X, got %#02X", protoVersion, p[0])
			}

			if p[3] != tc.atyp {
				t.Fatalf("expected address type to be %#02X, got %#02X", tc.atyp, p[3])
			}

			addrLen := 4 * p[3]
			addr, _ := netip.AddrFromSlice(p[4 : 4+addrLen])
			if !slices.Equal(addr.AsSlice(), tc.rep.bndAddr.Addr().AsSlice()) {
				t.Fatalf("IP addresses do not match: want %v got %v", tc.rep.bndAddr.Addr(), addr)
			}

			port := binary.BigEndian.Uint16(p[4+addrLen:])
			if port != tc.rep.bndAddr.Port() {
				t.Fatalf("ports do not match: want %v got %v", tc.rep.bndAddr.Port(), port)
			}
		})
	}
}
