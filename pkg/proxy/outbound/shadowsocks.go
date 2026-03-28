package outbound

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"kage/pkg/core"
	sscrypto "kage/pkg/crypto/shadowsocks"
	ssproto "kage/pkg/protocol/shadowsocks"
	"log/slog"
	"net"
)

type Shadowsocks struct {
	net.Conn
	
	Method   string
	enCipher *sscrypto.Cipher
	deCipher *sscrypto.Cipher
	
	readBuffer []byte
	
	readResponseHeaderOnce bool
	writeRequestHeaderOnce bool
	
	targetAddr     *core.Address
	initialPayload []byte
}

func NewShadowsocks(conn net.Conn, method string, enCipher *sscrypto.Cipher, targetAddr *core.Address, initialPayload []byte) *Shadowsocks {
	return &Shadowsocks{
		Conn:     conn,
		Method:   method,
		enCipher: enCipher,
		deCipher: nil,
		
		readBuffer: make([]byte, 0),
		
		readResponseHeaderOnce: false,
		writeRequestHeaderOnce: false,
		
		targetAddr:     targetAddr,
		initialPayload: initialPayload,
	}
}

func (s *Shadowsocks) Write(p []byte) (n int, err error) {
	var buf []byte
	if !s.writeRequestHeaderOnce {
		flHeader, vlHeader, err := ssproto.PackRequestHeader(s.targetAddr, s.initialPayload)
		if err != nil {
			return 0, err
		}
		buf = append(buf, s.enCipher.Salt...)
		buf = s.enCipher.Seal(buf, flHeader)
		buf = s.enCipher.Seal(buf, vlHeader)
		s.writeRequestHeaderOnce = true
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

func (s *Shadowsocks) Read(p []byte) (n int, err error) {
	if !s.readResponseHeaderOnce {
		saltSize := len(s.enCipher.Salt)
		headerBuf := make([]byte, 2*saltSize+27)
		if _, err := io.ReadFull(s.Conn, headerBuf); err != nil {
			return 0, err
		}
		
		deCipher, err := sscrypto.NewCipherWithSalt(s.Method, s.enCipher.Key, headerBuf[:saltSize])
		if err != nil {
			return 0, err
		}
		s.deCipher = deCipher
		
		data, err := s.deCipher.Open(nil, headerBuf[saltSize:])
		if err != nil {
			slog.Error("SS outbound: response header decrypt failed", "error", err)
			return 0, errors.New("shadowsocks: failed to open response fixed-length header")
		}
		
		if data[0] != 1 {
			return 0, errors.New("shadowsocks: invalid type in response fixed-length header")
		}
		
		if !bytes.Equal(data[9:9+saltSize], s.enCipher.Salt) {
			return 0, errors.New("shadowsocks: request salt mismatch in response header")
		}
		
		vlLen := binary.BigEndian.Uint16(data[9+saltSize:])
		if vlLen > 0 {
			vlBuf := make([]byte, int(vlLen)+16)
			if _, err := io.ReadFull(s.Conn, vlBuf); err != nil {
				return 0, err
			}
			vlData, err := s.deCipher.Open(nil, vlBuf)
			if err != nil {
				return 0, errors.New("shadowsocks: failed to open response variable-length header")
			}
			
			if len(vlData) > 0 {
				s.readBuffer = append(s.readBuffer, vlData...)
			}
		}
		
		s.readResponseHeaderOnce = true
	}
	
	if len(s.readBuffer) > 0 {
		n = copy(p, s.readBuffer)
		s.readBuffer = s.readBuffer[n:]
		return n, nil
	}
	
	chunkHeader := make([]byte, 18)
	if _, err := io.ReadFull(s.Conn, chunkHeader); err != nil {
		return 0, err
	}
	
	lenBuf, err := s.deCipher.Open(nil, chunkHeader)
	if err != nil {
		slog.Error("SS outbound: chunk length decrypt failed", "error", err)
		return 0, err
	}
	
	payloadLen := int(binary.BigEndian.Uint16(lenBuf))
	if payloadLen == 0 {
		return 0, io.EOF
	}
	
	fullPayloadBuf := make([]byte, payloadLen+16)
	if _, err := io.ReadFull(s.Conn, fullPayloadBuf); err != nil {
		return 0, err
	}
	
	payload, err := s.deCipher.Open(nil, fullPayloadBuf)
	if err != nil {
		slog.Error("SS outbound: chunk payload decrypt failed", "error", err)
		return 0, err
	}
	
	n = copy(p, payload)
	if n < len(payload) {
		s.readBuffer = append(s.readBuffer, payload[n:]...)
	}
	return n, nil
}

func (s *Shadowsocks) CloseWrite() error {
	if tc, ok := s.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
}
