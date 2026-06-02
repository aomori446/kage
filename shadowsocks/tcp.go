package shadowsocks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"kage/core"
	"net"
)

type Conn struct {
	net.Conn
	
	enCipher *Cipher
	deCipher *Cipher
	
	readBuffer []byte
	
	responseHeaderRead   bool
	requestHeaderWritten bool
	
	targetAddr     *core.Address
	initialPayload []byte
}

func NewConn(conn net.Conn, method string, psk []byte, targetAddr *core.Address, initialPayload []byte) (*Conn, error) {
	enCipher, err := NewCipher(method, psk)
	if err != nil {
		return nil, err
	}
	
	return &Conn{
		Conn:           conn,
		enCipher:       enCipher,
		targetAddr:     targetAddr,
		initialPayload: initialPayload,
	}, nil
}

func (s *Conn) Write(p []byte) (n int, err error) {
	var buf []byte
	if !s.requestHeaderWritten {
		flHeader, vlHeader, err := PackRequestHeader(s.targetAddr, s.initialPayload)
		if err != nil {
			return 0, err
		}
		
		buf = append(buf, s.enCipher.Salt...)
		buf = s.enCipher.Seal(buf, flHeader)
		buf = s.enCipher.Seal(buf, vlHeader)
		
		s.requestHeaderWritten = true
	}
	
	if len(p) > 0 {
		payloadSize := make([]byte, 2)
		binary.BigEndian.PutUint16(payloadSize, uint16(len(p)))
		
		buf = s.enCipher.Seal(buf, payloadSize)
		buf = s.enCipher.Seal(buf, p)
	}
	
	if len(buf) > 0 {
		_, err = s.Conn.Write(buf)
		if err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (s *Conn) Read(p []byte) (n int, err error) {
	if !s.responseHeaderRead {
		saltSize := len(s.enCipher.Salt)
		headerBuf := make([]byte, 2*saltSize+27)
		if _, err := io.ReadFull(s.Conn, headerBuf); err != nil {
			return 0, err
		}
		
		deCipher, err := NewCipherWithSalt(s.enCipher.Method, s.enCipher.Key, headerBuf[:saltSize])
		if err != nil {
			return 0, err
		}
		s.deCipher = deCipher
		
		data, err := s.deCipher.Open(nil, headerBuf[saltSize:])
		if err != nil {
			return 0, errors.New("shadowsocks: failed to open response fixed-length header")
		}
		
		if data[0] != 1 {
			return 0, errors.New("shadowsocks: invalid type in response fixed-length header")
		}
		
		if !bytes.Equal(data[9:9+saltSize], s.enCipher.Salt) {
			return 0, errors.New("shadowsocks: request salt mismatch in response header")
		}
		
		vlLen := binary.BigEndian.Uint16(data[9+saltSize:])
		vlBuf := make([]byte, int(vlLen)+16)
		if _, err := io.ReadFull(s.Conn, vlBuf); err != nil {
			return 0, err
		}
		vlData, err := s.deCipher.Open(nil, vlBuf)
		if err != nil {
			return 0, errors.New("shadowsocks: failed to open response variable-length header")
		}
		s.readBuffer = append(s.readBuffer, vlData...)
		
		s.responseHeaderRead = true
	}
	
	if len(s.readBuffer) > 0 {
		n = copy(p, s.readBuffer)
		s.readBuffer = s.readBuffer[n:]
		return n, nil
	}
	
	chunkHeader := make([]byte, 18)
	if _, err = io.ReadFull(s.Conn, chunkHeader); err != nil {
		return 0, err
	}
	
	lenBuf, err := s.deCipher.Open(nil, chunkHeader)
	if err != nil {
		return 0, err
	}
	
	payloadLen := binary.BigEndian.Uint16(lenBuf)
	payloadBuf := make([]byte, payloadLen+16)
	if _, err = io.ReadFull(s.Conn, payloadBuf); err != nil {
		return 0, err
	}
	payload, err := s.deCipher.Open(nil, payloadBuf)
	if err != nil {
		return 0, err
	}
	
	n = copy(p, payload)
	if n < len(payload) {
		s.readBuffer = append(s.readBuffer, payload[n:]...)
	}
	return n, nil
}

func (s *Conn) CloseWrite() error {
	if tc, ok := s.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
}
