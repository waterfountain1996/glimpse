package socks

const Version uint8 = 5

type AuthMethod uint8

const (
	AuthNone     AuthMethod = 0
	AuthGssapi   AuthMethod = 1
	AuthPassword AuthMethod = 2
	AuthInvalid  AuthMethod = 0xFF
)

type Cmd uint8

const (
	CmdConnect      Cmd = 1
	CmdBind         Cmd = 2
	CmdUDPAssociate Cmd = 3
)

type Atyp uint8

const (
	AtypIP4    Atyp = 1
	AtypDomain Atyp = 3
	AtypIP6    Atyp = 4
)

type Reply uint8

const (
	ReplySuccess          Reply = 0
	ReplyError            Reply = 1
	ReplyForbidden        Reply = 2
	ReplyNetUnreachable   Reply = 3
	ReplyHostUnreachable  Reply = 4
	ReplyRefused          Reply = 5
	ReplyExpired          Reply = 6
	ReplyCmdNotSupported  Reply = 7
	ReplyAtypNotSupported Reply = 8
)
