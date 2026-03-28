package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
)

type Counter struct {
	buf [12]byte
	mu  sync.Mutex
}

func (c *Counter) Count() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	for i := 0; i < 12; i++ {
		c.buf[i]++
		if c.buf[i] != 0 {
			break
		}
	}
}

func (c *Counter) Nonce() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	nonce := make([]byte, 12)
	copy(nonce, c.buf[:])
	return nonce
}

type Cipher struct {
	Method  string
	Key     []byte
	Salt    []byte
	Counter *Counter
	AEAD    cipher.AEAD
}

func NewCipherWithSalt(method string, key, salt []byte) (*Cipher, error) {
	sessionSubkey, err := Blake3DeriveKey(key, salt)
	if err != nil {
		return nil, err
	}
	
	var aead cipher.AEAD
	switch method {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		block, err := aes.NewCipher(sessionSubkey)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	case "2022-blake3-chacha20-poly1305":
		var err error
		aead, err = chacha20poly1305.New(sessionSubkey)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported method: %s", method)
	}
	
	return &Cipher{
		Method:  method,
		Key:     key,
		Salt:    salt,
		Counter: new(Counter),
		AEAD:    aead,
	}, nil
}

func NewCipher(method string, key []byte) (*Cipher, error) {
	var saltSize int
	switch method {
	case "2022-blake3-aes-128-gcm":
		saltSize = 16
	case "2022-blake3-aes-256-gcm":
		saltSize = 32
	case "2022-blake3-chacha20-poly1305":
		saltSize = 32
	default:
		return nil, fmt.Errorf("unsupported method: %s", method)
	}
	
	if len(key) != saltSize {
		return nil, errors.New("invalid key length for shadowsocks 2022")
	}
	
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return NewCipherWithSalt(method, key, salt)
}

func (c *Cipher) Seal(dst []byte, plaintext []byte) []byte {
	nonce := c.Counter.Nonce()
	c.Counter.Count()
	return c.AEAD.Seal(dst, nonce, plaintext, nil)
}

func (c *Cipher) Open(dst []byte, ciphertext []byte) ([]byte, error) {
	nonce := c.Counter.Nonce()
	c.Counter.Count()
	return c.AEAD.Open(dst, nonce, ciphertext, nil)
}

func Blake3DeriveKey(key, salt []byte) ([]byte, error) {
	deriveKey := make([]byte, len(key))
	blake3.DeriveKey("shadowsocks 2022 session subkey", append(key, salt...), deriveKey)
	return deriveKey, nil
}
