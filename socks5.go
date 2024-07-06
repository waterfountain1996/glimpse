package glimpse

import "errors"

const protoVersion = 0x05

var errInvalidVersion = errors.New("invalid protocol version")

const (
	cmdConnect      byte = 0x01
	cmdBind         byte = 0x02
	cmdUdpAssociate byte = 0x03
)

const (
	atypIPv4       byte = 0x01
	atypDomainName byte = 0x03
	atypIPv6       byte = 0x04
)
