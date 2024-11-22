package main

import "errors"

// SOCKS5 protocol version.
const protocolVersion = byte(0x05)

var errInvalidVersion = errors.New("invalid protocol version")

const (
	methodNoAuth   = byte(0x00)
	methodPassword = byte(0x02)
	methodInvalid  = byte(0xFF)
)

const (
	cmdConnect      = byte(0x01)
	cmdBind         = byte(0x02)
	cmdUDPAssociate = byte(0x03)
)

const (
	atypIPv4 = byte(0x01)
	atypFQDN = byte(0x03)
	atypIPv6 = byte(0x04)
)

const (
	repSuccess          = byte(0x00)
	repFailure          = byte(0x01)
	repForbidden        = byte(0x02)
	repNetUnreachable   = byte(0x03)
	repHostUnreachable  = byte(0x04)
	repRefused          = byte(0x05)
	repTTLExpired       = byte(0x06)
	repCmdNotSupported  = byte(0x07)
	repAtypNotSupported = byte(0x08)
)
