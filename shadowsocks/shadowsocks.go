package shadowsocks

import (
	"errors"
	"time"
)

var (
	ErrHeaderType = errors.New("shadowsocks: invalid header type")
)

type HeaderTypeStream byte

const (
	HeaderTypeClientStream HeaderTypeStream = 0x00
	HeaderTypeServerStream HeaderTypeStream = 0x01
)

const (
	MaxPaddingLength        = 900
	MaxInitialPayloadLength = 8192
	MaxPayloadLength        = 0xFFFF
	HandshakeTimeout        = 5 * time.Second
)
