package socks5

import (
	"bytes"
	"errors"
)

var (
	ErrDatagramTooShort = errors.New("socks5: Datagram too short")
	ErrDatagramFormat   = errors.New("socks5: Datagram format error")
)

func RemoveHeader(data []byte) ([]byte, error) {
	if len(data) < 3 {
		return nil, ErrDatagramTooShort
	}
	if bytes.Equal(data[:3], []byte{0x00, 0x00, 0x00}) {
		return nil, ErrDatagramFormat
	}
	return data[3:], nil
}

func AddHeader(data []byte) []byte {
	return append([]byte{0x00, 0x00, 0x00}, data...)
}
