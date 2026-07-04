package shadowsocks

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/aomori446/kage/core"
)

var (
	ErrPayloadTooShort  = errors.New("udp payload too short")
	ErrBadHeaderType    = errors.New("bad header type")
	ErrTimestampExpired = errors.New("timestamp expired (>30s)")
	ErrSessionNotFound  = errors.New("client session not found")
)

type UDPSession struct {
	ID     []byte
	Cipher *Cipher
}

func NewUDPSession(method string, psk []byte) (*UDPSession, error) {
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("generate session id: %w", err)
	}
	
	c, err := NewCipherWithSalt(method, psk, id)
	if err != nil {
		return nil, fmt.Errorf("create session cipher: %w", err)
	}
	
	return &UDPSession{
		ID:     id,
		Cipher: c,
	}, nil
}

func (s *UDPSession) SeparateHeader() []byte {
	sh := make([]byte, 16)
	copy(sh[:8], s.ID[:8])
	nonce := s.Cipher.Counter.Nonce()
	copy(sh[8:], nonce[:8])
	return sh
}

type UDPRelay struct {
	Method      string
	PSK         []byte
	BlockCipher cipher.Block
	ServerConn  *net.UDPConn

	// client session ID -> target address
	targetByID sync.Map
	// target address string -> client UDPSession
	sessionsByTarget sync.Map
	// server session ID -> server session *Cipher
	serverCiphers sync.Map
}

func NewUDPRelay(method string, psk []byte, serverAddr string) (*UDPRelay, error) {
	block, err := NewBlockCipher(psk)
	if err != nil {
		return nil, err
	}
	
	sAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, err
	}
	serverConn, err := net.DialUDP("udp", nil, sAddr)
	if err != nil {
		return nil, err
	}
	
	return &UDPRelay{
		Method:      method,
		PSK:         psk,
		BlockCipher: block,
		ServerConn:  serverConn,
	}, nil
}

func (c *UDPRelay) WriteTo(p []byte, target *core.Address) (int, error) {
	session, err := c.getOrCreateSession(target)
	if err != nil {
		return 0, err
	}
	
	separateHeader := session.SeparateHeader()
	enSeparateHeader := make([]byte, 16)
	c.BlockCipher.Encrypt(enSeparateHeader, separateHeader)
	
	messageHeader, err := c.buildMessageHeader()
	if err != nil {
		return 0, err
	}
	
	targetBytes := target.Bytes()
	body := append(messageHeader, targetBytes...)
	body = append(body, p...)
	
	enBody := session.Cipher.AEAD.Seal(nil, separateHeader[4:16], body, nil)
	session.Cipher.Counter.Count()
	
	packet := append(enSeparateHeader, enBody...)
	_, err = c.ServerConn.Write(packet)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *UDPRelay) ReadFrom(p []byte) (int, *core.Address, error) {
	buf := make([]byte, 65535)
	for {
		rn, err := c.ServerConn.Read(buf)
		if err != nil {
			return 0, nil, err
		}
		
		if rn < 16 {
			continue
		}
		
		deHeader := make([]byte, 16)
		c.BlockCipher.Decrypt(deHeader, buf[:16])
		
		serverCipher, err := c.getOrCreateServerCipher(deHeader[:8])
		if err != nil {
			continue
		}
		
		aeadNonce := make([]byte, 12)
		copy(aeadNonce[:4], deHeader[4:8])
		copy(aeadNonce[4:], deHeader[8:16])
		
		deBody, err := serverCipher.AEAD.Open(nil, aeadNonce, buf[16:rn], nil)
		if err != nil {
			continue
		}
		
		body, clientSessionID, err := c.parseMessageBody(deBody)
		if err != nil {
			continue
		}
		
		v, ok := c.targetByID.Load(string(clientSessionID))
		if !ok {
			continue
		}
		
		n := copy(p, body)
		return n, v.(*core.Address), nil
	}
}

func (c *UDPRelay) Close() error {
	return c.ServerConn.Close()
}

func (c *UDPRelay) getOrCreateSession(target *core.Address) (*UDPSession, error) {
	key := target.String()
	if v, ok := c.sessionsByTarget.Load(key); ok {
		return v.(*UDPSession), nil
	}
	
	session, err := NewUDPSession(c.Method, c.PSK)
	if err != nil {
		return nil, err
	}
	
	actual, loaded := c.sessionsByTarget.LoadOrStore(key, session)
	if loaded {
		return actual.(*UDPSession), nil
	}
	
	c.targetByID.Store(string(session.ID), target)
	return session, nil
}

func (c *UDPRelay) getOrCreateServerCipher(sessionID []byte) (*Cipher, error) {
	key := string(sessionID)
	if v, ok := c.serverCiphers.Load(key); ok {
		return v.(*Cipher), nil
	}
	
	cipher, err := NewCipherWithSalt(c.Method, c.PSK, sessionID)
	if err != nil {
		return nil, err
	}
	
	c.serverCiphers.Store(key, cipher)
	return cipher, nil
}

func (c *UDPRelay) buildMessageHeader() ([]byte, error) {
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

func (c *UDPRelay) parseMessageBody(deBody []byte) (payload, clientSessionID []byte, err error) {
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
	clientSessionID = make([]byte, 8)
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
