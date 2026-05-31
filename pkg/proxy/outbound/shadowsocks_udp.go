package outbound

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	sscrypto "kage/pkg/crypto/shadowsocks"
	"math/big"
	"net"
	"sync"
	"time"
)

var (
	ErrPayloadTooShort  = errors.New("udp payload too short")
	ErrBadHeaderType    = errors.New("bad header type")
	ErrTimestampExpired = errors.New("timestamp expired (>30s)")
	ErrSessionNotFound  = errors.New("client session not found")
)

type UDPSession struct {
	ID     []byte
	Cipher *sscrypto.Cipher
}

func NewUDPSession(method string, psk []byte) (*UDPSession, error) {
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("generate session id: %w", err)
	}
	
	cipher, err := sscrypto.NewCipherWithSalt(method, psk, id)
	if err != nil {
		return nil, fmt.Errorf("create session cipher: %w", err)
	}
	
	return &UDPSession{
		ID:     id,
		Cipher: cipher,
	}, nil
}

func (s *UDPSession) SeparateHeader() []byte {
	sh := make([]byte, 16)
	copy(sh[:8], s.ID[:8])
	nonce := s.Cipher.Counter.Nonce()
	copy(sh[8:], nonce[:8])
	return sh
}

type ShadowsocksUDP struct {
	Method      string
	PSK         []byte
	BlockCipher cipher.Block
	
	ServerAddr *net.UDPAddr
	
	// server session ID -> server session cipher
	serverSessions sync.Map
	// client addr -> client session
	clientSessions sync.Map
	// client session ID -> client addr
	clientSessionIDs sync.Map
}

func NewShadowsocksUDP(method string, psk []byte, serverAddr string) (*ShadowsocksUDP, error) {
	block, err := sscrypto.NewBlockCipher(psk)
	if err != nil {
		return nil, err
	}
	
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, err
	}
	
	return &ShadowsocksUDP{
		Method:      method,
		PSK:         psk,
		BlockCipher: block,
		ServerAddr:  addr,
	}, nil
}

func (s *ShadowsocksUDP) Pack(clientAddr *net.UDPAddr, data []byte) ([]byte, error) {
	session, err := s.getOrCreateClientSession(clientAddr)
	if err != nil {
		return nil, err
	}
	
	separateHeader := session.SeparateHeader()
	enSeparateHeader := make([]byte, 16)
	s.BlockCipher.Encrypt(enSeparateHeader, separateHeader)
	
	messageHeader, err := s.buildMessageHeader()
	if err != nil {
		return nil, err
	}
	
	body := append(messageHeader, data...)
	
	aeadNonce := make([]byte, 12)
	copy(aeadNonce[:4], session.ID[4:8])
	copy(aeadNonce[4:], separateHeader[8:16])
	
	enBody := session.Cipher.AEAD.Seal(nil, aeadNonce, body, nil)
	session.Cipher.Counter.Count()
	
	return append(enSeparateHeader, enBody...), nil
}

func (s *ShadowsocksUDP) Unpack(payload []byte) ([]byte, *net.UDPAddr, error) {
	if len(payload) < 16 {
		return nil, nil, ErrPayloadTooShort
	}
	
	deHeader := make([]byte, 16)
	s.BlockCipher.Decrypt(deHeader, payload[:16])
	
	serverCipher, err := s.getOrCreateServerCipher(deHeader[:8])
	if err != nil {
		return nil, nil, err
	}
	
	aeadNonce := make([]byte, 12)
	copy(aeadNonce[:4], deHeader[4:8])
	copy(aeadNonce[4:], deHeader[8:16])
	
	deBody, err := serverCipher.AEAD.Open(nil, aeadNonce, payload[16:], nil)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt body: %w", err)
	}
	
	body, clientSessionID, err := s.resolveBody(deBody)
	if err != nil {
		return nil, nil, err
	}
	
	v, ok := s.clientSessionIDs.Load(string(clientSessionID))
	if !ok {
		return nil, nil, ErrSessionNotFound
	}
	
	return body, v.(*net.UDPAddr), nil
}

func (s *ShadowsocksUDP) getOrCreateClientSession(addr *net.UDPAddr) (*UDPSession, error) {
	key := addr.String()
	if v, ok := s.clientSessions.Load(key); ok {
		return v.(*UDPSession), nil
	}
	
	session, err := NewUDPSession(s.Method, s.PSK)
	if err != nil {
		return nil, err
	}
	
	s.clientSessions.Store(key, session)
	s.clientSessionIDs.Store(string(session.ID), addr)
	return session, nil
}

func (s *ShadowsocksUDP) getOrCreateServerCipher(sessionID []byte) (*sscrypto.Cipher, error) {
	key := string(sessionID)
	if v, ok := s.serverSessions.Load(key); ok {
		return v.(*sscrypto.Cipher), nil
	}
	
	cipher, err := sscrypto.NewCipherWithSalt(s.Method, s.PSK, sessionID)
	if err != nil {
		return nil, err
	}
	
	s.serverSessions.Store(key, cipher)
	return cipher, nil
}

func (s *ShadowsocksUDP) buildMessageHeader() ([]byte, error) {
	mh := []byte{0x00} // Type: Client-to-Server
	
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().Unix()))
	mh = append(mh, timestamp...)
	
	pl, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		return nil, err
	}
	paddingLength := uint16(pl.Int64())
	padding := make([]byte, paddingLength+2)
	binary.BigEndian.PutUint16(padding, paddingLength)
	if _, err = rand.Read(padding[2:]); err != nil {
		return nil, err
	}
	
	return append(mh, padding...), nil
}

func (s *ShadowsocksUDP) resolveBody(deBody []byte) ([]byte, []byte, error) {
	if len(deBody) < 1 {
		return nil, nil, ErrPayloadTooShort
	}
	if deBody[0] != 1 { // Type: Server-to-Client
		return nil, nil, ErrBadHeaderType
	}
	deBody = deBody[1:]
	
	if len(deBody) < 8 {
		return nil, nil, ErrPayloadTooShort
	}
	t := time.Unix(int64(binary.BigEndian.Uint64(deBody[:8])), 0)
	if time.Since(t) > 30*time.Second {
		return nil, nil, ErrTimestampExpired
	}
	deBody = deBody[8:]
	
	if len(deBody) < 8 {
		return nil, nil, ErrPayloadTooShort
	}
	clientSessionID := make([]byte, 8)
	copy(clientSessionID, deBody[:8])
	deBody = deBody[8:]
	
	if len(deBody) < 2 {
		return nil, nil, ErrPayloadTooShort
	}
	paddingLen := int(binary.BigEndian.Uint16(deBody))
	deBody = deBody[2:]
	
	if len(deBody) < paddingLen {
		return nil, nil, ErrPayloadTooShort
	}
	deBody = deBody[paddingLen:]
	
	return deBody, clientSessionID, nil
}
