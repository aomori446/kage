package shadowsocks

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
	
	"golang.org/x/sync/errgroup"
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

type UDPClient struct {
	Method      string
	PSK         []byte
	BlockCipher cipher.Block
	
	ClientConn *net.UDPConn
	ServerConn *net.UDPConn
	
	// server session ID → server session *Cipher
	serverCiphers sync.Map
	// client addr → client *UDPSession
	clientSessions sync.Map
	// client session ID → client net.Addr (reverse index for Unpack)
	clientAddrByID sync.Map
}

func NewUDPClient(method string, psk []byte, listenAddr, serverAddr string) (*UDPClient, error) {
	block, err := NewBlockCipher(psk)
	if err != nil {
		return nil, err
	}
	
	lnAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	clientConn, err := net.ListenUDP("udp", lnAddr)
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
	
	return &UDPClient{
		Method:      method,
		PSK:         psk,
		BlockCipher: block,
		ClientConn:  clientConn,
		ServerConn:  serverConn,
	}, nil
}

func (c *UDPClient) Run(ctx context.Context) error {
	var errGroup errgroup.Group
	
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	
	errGroup.Go(func() error {
		<-ctx.Done()
		c.ClientConn.Close()
		c.ServerConn.Close()
		return nil
	})
	
	errGroup.Go(func() error {
		defer cancel()
		
		buf := make([]byte, 65535)
		for {
			n, fromAddr, err := c.ClientConn.ReadFrom(buf)
			if err != nil {
				return fmt.Errorf("read UDP packet from client connection failed: %w", err)
			}
			
			packed, err := c.EncryptPacket(fromAddr, buf[:n])
			if err != nil {
				return fmt.Errorf("pack UDP packet failed: %w", err)
			}
			
			_, err = c.ServerConn.Write(packed)
			if err != nil {
				return fmt.Errorf("write UDP packet to server connection failed: %w", err)
			}
		}
	})
	
	errGroup.Go(func() error {
		defer cancel()
		
		buf := make([]byte, 65535)
		for {
			n, fromAddr, err := c.ServerConn.ReadFrom(buf)
			if err != nil {
				return fmt.Errorf("read UDP packet from server connection failed: %w", err)
			}
			
			if fromAddr.String() != c.ServerConn.RemoteAddr().String() {
				return fmt.Errorf("got different address from server address: got %s, want:%s", fromAddr.String(), c.ServerConn.RemoteAddr().String())
			}
			
			unpacked, toAddr, err := c.DecryptPacket(buf[:n])
			if err != nil {
				return fmt.Errorf("unpack UDP packet failed: %w", err)
			}
			
			_, err = c.ClientConn.WriteTo(unpacked, toAddr)
			if err != nil {
				return fmt.Errorf("write UDP packet to client connection failed: %w", err)
			}
		}
	})
	
	return errGroup.Wait()
}

func (c *UDPClient) EncryptPacket(clientAddr net.Addr, data []byte) ([]byte, error) {
	session, err := c.getOrCreateClientSession(clientAddr)
	if err != nil {
		return nil, err
	}
	
	separateHeader := session.SeparateHeader()
	enSeparateHeader := make([]byte, 16)
	c.BlockCipher.Encrypt(enSeparateHeader, separateHeader)
	
	messageHeader, err := c.buildMessageHeader()
	if err != nil {
		return nil, err
	}
	
	body := append(messageHeader, data...)
	
	enBody := session.Cipher.AEAD.Seal(nil, separateHeader[4:16], body, nil)
	session.Cipher.Counter.Count()
	
	return append(enSeparateHeader, enBody...), nil
}

func (c *UDPClient) DecryptPacket(payload []byte) ([]byte, net.Addr, error) {
	if len(payload) < 16 {
		return nil, nil, ErrPayloadTooShort
	}
	
	deHeader := make([]byte, 16)
	c.BlockCipher.Decrypt(deHeader, payload[:16])
	
	serverCipher, err := c.getOrCreateServerCipher(deHeader[:8])
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
	
	body, clientSessionID, err := c.parseMessageBody(deBody)
	if err != nil {
		return nil, nil, err
	}
	
	v, ok := c.clientAddrByID.Load(string(clientSessionID))
	if !ok {
		return nil, nil, ErrSessionNotFound
	}
	
	return body, v.(net.Addr), nil
}

func (c *UDPClient) Close() error {
	c.ClientConn.Close()
	c.ServerConn.Close()
	return nil
}

func (c *UDPClient) getOrCreateClientSession(addr net.Addr) (*UDPSession, error) {
	key := addr.String()
	if v, ok := c.clientSessions.Load(key); ok {
		return v.(*UDPSession), nil
	}
	
	session, err := NewUDPSession(c.Method, c.PSK)
	if err != nil {
		return nil, err
	}
	
	actual, loaded := c.clientSessions.LoadOrStore(key, session)
	if loaded {
		return actual.(*UDPSession), nil
	}
	
	c.clientAddrByID.Store(string(session.ID), addr)
	return session, nil
}

func (c *UDPClient) getOrCreateServerCipher(sessionID []byte) (*Cipher, error) {
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

func (c *UDPClient) buildMessageHeader() ([]byte, error) {
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

func (c *UDPClient) parseMessageBody(deBody []byte) (payload, clientSessionID []byte, err error) {
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
