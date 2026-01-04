package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"sync"

	"github.com/aomori446/kage/config"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrCipherMethod  = errors.New("shadowsocks: cipherMethod not supported")
	ErrCipherKeySize = errors.New("shadowsocks: invalid key size")
)

func NewCipher(key, salt []byte, method config.CipherMethod) (*Cipher, error) {
	switch method {
	case config.CipherMethod2022blake3aes128gcm:
		return NewAES128GCM(key, salt)
	case config.CipherMethod2022blake3aes256gcm:
		return NewAES256GCM(key, salt)
	case config.CipherMethod2022blake3chacha20poly1305:
		return NewChacha20Poly1305(key, salt)
	default:
		return nil, ErrCipherMethod
	}
}

func NewAES128GCM(key, salt []byte) (*Cipher, error) {
	if len(key) != 16 {
		return nil, ErrCipherKeySize
	}

	deriveKey, err := Blake3DeriveKey(key, salt)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(deriveKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		aead:    gcm,
		counter: new(Counter),
		key:     key,
		salt:    salt,
		method:  config.CipherMethod2022blake3aes128gcm,
	}, nil
}

func NewAES256GCM(key, salt []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, ErrCipherKeySize
	}

	deriveKey, err := Blake3DeriveKey(key, salt)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(deriveKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		aead:    gcm,
		counter: new(Counter),
		key:     key,
		salt:    salt,
		method:  config.CipherMethod2022blake3aes256gcm,
	}, nil
}

func NewChacha20Poly1305(key []byte, salt []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, ErrCipherKeySize
	}
	deriveKey, err := Blake3DeriveKey(key, salt)
	if err != nil {
		return nil, err
	}
	c, err := chacha20poly1305.New(deriveKey)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		aead:    c,
		counter: new(Counter),
		key:     key,
		salt:    salt,
		method:  config.CipherMethod2022blake3chacha20poly1305,
	}, nil
}

type Counter struct {
	buf [12]byte
	mu  sync.Mutex
}

func (c *Counter) Count() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range c.buf {
		if c.buf[i] == 255 {
			c.buf[i] = 0
		} else {
			c.buf[i]++
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

func NewSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

type Cipher struct {
	aead    cipher.AEAD
	counter *Counter

	key    []byte
	salt   []byte
	method config.CipherMethod
}

func (c *Cipher) Overhead() int {
	return c.aead.Overhead()
}

func (c *Cipher) Seal(dst, plaintext []byte) []byte {
	dst = c.aead.Seal(dst, c.counter.Nonce(), plaintext, nil)
	c.counter.Count()
	return dst
}

func (c *Cipher) Seals(dst []byte, plaintexts ...[]byte) []byte {
	for _, plaintext := range plaintexts {
		dst = c.Seal(dst, plaintext)
	}
	return dst
}

func (c *Cipher) SealWithNonce(dst, nonce, plaintext []byte) []byte {
	dst = c.aead.Seal(dst, nonce, plaintext, nil)
	c.counter.Count()
	return dst
}

func (c *Cipher) Open(dst, ciphertext []byte) ([]byte, error) {
	dst, err := c.aead.Open(dst, c.counter.Nonce(), ciphertext, nil)
	if err != nil {
		return nil, err
	}
	c.counter.Count()
	return dst, nil
}

func (c *Cipher) OpenWithNonce(dst, nonce, ciphertext []byte) ([]byte, error) {
	dst, err := c.aead.Open(dst, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	c.counter.Count()
	return dst, nil
}

func (c *Cipher) ReNew(salt []byte) (*Cipher, error) {
	return NewCipher(c.key, salt, c.method)
}

func (c *Cipher) Salt() []byte {
	return c.salt
}

func (c *Cipher) Nonce() []byte {
	return c.counter.Nonce()
}

func Blake3DeriveKey(key, salt []byte) ([]byte, error) {
	deriveKey := make([]byte, len(key))
	blake3.DeriveKey("shadowsocks 2022 session subkey", append(key, salt...), deriveKey)
	return deriveKey, nil
}
