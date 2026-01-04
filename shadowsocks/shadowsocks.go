package shadowsocks

import (
	"errors"
)

var (
	ErrHeaderType = errors.New("shadowsocks: invalid header type")
)

type HeaderTypeStream byte

const (
	HeaderTypeClientStream HeaderTypeStream = 0x00
	HeaderTypeServerStream HeaderTypeStream = 0x01
)

type HeaderTypePacket byte

const (
	HeaderTypeClientPacket HeaderTypePacket = 0
	HeaderTypeServerPacket HeaderTypePacket = 1
)

const (
	MaxPaddingLength        = 900
	MaxInitialPayloadLength = 8192
	MaxPayloadLength        = 0xFFFF
)
