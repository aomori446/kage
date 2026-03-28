package socks5

import (
	"errors"
	"fmt"
	"io"
	"kage/pkg/core"
	"net"
	"slices"
	"time"
)

var (
	ErrVersionNotSupported = errors.New("socks5: version not supported")
	ErrCommandNotSupported = errors.New("socks5: command not supported")
	ErrMethodsCount        = errors.New("socks5: invalid methods count")
	ErrNoAcceptableMethods = errors.New("socks5: no acceptable methods")
)

type HandshakeResult struct {
	TargetAddress *core.Address
	Command       byte
	
	InitialPayload []byte
}

func Handshake(conn net.Conn, associateBindAddr string, fastOpen bool) (*HandshakeResult, error) {
	associateAddress, err := core.ParseAddress(associateBindAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse associate addr: %w", err)
	}
	
	if err = auth(conn); err != nil {
		return nil, err
	}
	
	b := make([]byte, 3)
	if _, err = io.ReadFull(conn, b); err != nil {
		return nil, fmt.Errorf("failed to read request header: %w", err)
	}
	
	if b[0] != 0x05 {
		return nil, ErrVersionNotSupported
	}
	
	switch b[1] {
	case 0x01, 0x03:
	default:
		conn.Write([]byte{0x05, 0x07, 0x00, byte(core.AtypIPV4), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return nil, ErrCommandNotSupported
	}
	
	addr, err := core.ReadAddress(conn)
	if errors.Is(err, core.ErrAddressTypeNotSupported) {
		conn.Write([]byte{0x05, 0x08, 0x00, byte(core.AtypIPV4), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return nil, core.ErrAddressTypeNotSupported
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read target address: %w", err)
	}
	
	if b[1] == 0x01 {
		_, err = conn.Write(append([]byte{0x05, 0x00, 0x00}, core.EmptyAddress().Bytes()...))
		if err != nil {
			return nil, fmt.Errorf("failed to write connect response: %w", err)
		}
	} else {
		_, err = conn.Write(append([]byte{0x05, 0x00, 0x00}, associateAddress.Bytes()...))
		if err != nil {
			return nil, fmt.Errorf("failed to write associate response: %w", err)
		}
	}
	
	result := &HandshakeResult{
		TargetAddress: addr,
		Command:       b[1],
	}
	
	if fastOpen {
		payload, err := readInitialPayload(conn)
		if err != nil {
			return nil, fmt.Errorf("failed to read initial payload: %w", err)
		}
		result.InitialPayload = payload
	}
	
	return result, nil
}

func readInitialPayload(conn net.Conn) ([]byte, error) {
	if err := conn.SetDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		return nil, err
	}
	defer conn.SetDeadline(time.Time{})
	
	buf := make([]byte, 32*1024)
	n, err := conn.Read(buf)
	
	if n > 0 {
		return buf[:n], nil
	}
	
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, nil
		}
		return nil, err
	}
	
	return nil, nil
}

func auth(conn net.Conn) error {
	if err := conn.SetDeadline(time.Now().Add(time.Second * 5)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})
	
	buf := make([]byte, 255)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		if errors.Is(err, io.EOF) {
			return err
		}
		return fmt.Errorf("failed to read auth header: %w", err)
	}
	
	if buf[0] != 0x05 {
		return fmt.Errorf("%w: got %d", ErrVersionNotSupported, buf[0])
	}
	
	nMethods := int(buf[1])
	if nMethods < 1 {
		return ErrMethodsCount
	}
	
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return fmt.Errorf("failed to read auth methods: %w", err)
	}
	
	if !slices.Contains(buf[:nMethods], 0x00) {
		conn.Write([]byte{0x05, 0xFF})
		return ErrNoAcceptableMethods
	}
	
	var err error
	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		return fmt.Errorf("failed to write auth response: %w", err)
	}
	
	return nil
}
