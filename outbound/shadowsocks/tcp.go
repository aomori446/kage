package shadowsocks

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/aomori446/kage/core"

	"golang.org/x/sync/errgroup"
)

type Conn struct {
	*net.TCPConn

	enCipher *Cipher
	deCipher *Cipher

	readBuffer         []byte
	responseHeaderRead bool
}

func NewConn(serverAddr string, method string, psk []byte, targetAddr *core.Address, initialPayload []byte) (*Conn, error) {
	conn, err := net.DialTimeout("tcp", serverAddr, time.Second*3)
	if err != nil {
		return nil, err
	}

	enCipher, err := NewCipher(method, psk)
	if err != nil {
		return nil, err
	}

	c := &Conn{
		TCPConn:  conn.(*net.TCPConn),
		enCipher: enCipher,
	}

	if err := c.writeRequestHeader(targetAddr, initialPayload); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Conn) writeRequestHeader(targetAddr *core.Address, initialPayload []byte) error {
	flHeader, vlHeader, err := PackRequestHeader(targetAddr, initialPayload)
	if err != nil {
		return err
	}

	buf := append([]byte(nil), c.enCipher.Salt...)
	buf = c.enCipher.Seal(buf, flHeader)
	buf = c.enCipher.Seal(buf, vlHeader)

	_, err = c.TCPConn.Write(buf)
	return err
}

func (c *Conn) Write(p []byte) (n int, err error) {
	payloadSize := make([]byte, 2)
	binary.BigEndian.PutUint16(payloadSize, uint16(len(p)))

	buf := c.enCipher.Seal(nil, payloadSize)
	buf = c.enCipher.Seal(buf, p)

	_, err = c.TCPConn.Write(buf)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *Conn) Read(p []byte) (n int, err error) {
	if !c.responseHeaderRead {
		saltSize := len(c.enCipher.Salt)
		headerBuf := make([]byte, 2*saltSize+27)
		if _, err := io.ReadFull(c.TCPConn, headerBuf); err != nil {
			return 0, err
		}

		deCipher, err := NewCipherWithSalt(c.enCipher.Method, c.enCipher.Key, headerBuf[:saltSize])
		if err != nil {
			return 0, err
		}
		c.deCipher = deCipher

		data, err := c.deCipher.Open(nil, headerBuf[saltSize:])
		if err != nil {
			return 0, errors.New("shadowsocks: failed to open response fixed-length header")
		}

		if data[0] != 1 {
			return 0, errors.New("shadowsocks: invalid type in response fixed-length header")
		}

		if !bytes.Equal(data[9:9+saltSize], c.enCipher.Salt) {
			return 0, errors.New("shadowsocks: request salt mismatch in response header")
		}

		vlLen := binary.BigEndian.Uint16(data[9+saltSize:])
		vlBuf := make([]byte, int(vlLen)+16)
		if _, err := io.ReadFull(c.TCPConn, vlBuf); err != nil {
			return 0, err
		}
		vlData, err := c.deCipher.Open(nil, vlBuf)
		if err != nil {
			return 0, errors.New("shadowsocks: failed to open response variable-length header")
		}
		c.readBuffer = append(c.readBuffer, vlData...)

		c.responseHeaderRead = true
	}

	if len(c.readBuffer) > 0 {
		n = copy(p, c.readBuffer)
		c.readBuffer = c.readBuffer[n:]
		return n, nil
	}

	chunkHeader := make([]byte, 18)
	if _, err = io.ReadFull(c.TCPConn, chunkHeader); err != nil {
		return 0, err
	}

	lenBuf, err := c.deCipher.Open(nil, chunkHeader)
	if err != nil {
		return 0, err
	}

	payloadLen := binary.BigEndian.Uint16(lenBuf)
	payloadBuf := make([]byte, payloadLen+16)
	if _, err = io.ReadFull(c.TCPConn, payloadBuf); err != nil {
		return 0, err
	}
	payload, err := c.deCipher.Open(nil, payloadBuf)
	if err != nil {
		return 0, err
	}

	n = copy(p, payload)
	if n < len(payload) {
		c.readBuffer = append(c.readBuffer, payload[n:]...)
	}
	return n, nil
}

func (c *Conn) RelayWith(ctx context.Context, conn net.Conn) error {
	var errGroup errgroup.Group

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	halfClosed := make(chan struct{}, 2)
	defer close(halfClosed)
	go func() {
		<-halfClosed
		<-halfClosed
		cancel()
	}()

	errGroup.Go(func() error {
		<-ctx.Done()
		c.Close()
		conn.Close()
		return ctx.Err()
	})

	errGroup.Go(func() error {
		_, err := io.Copy(conn, c)
		if hc, ok := conn.(HalfCloser); ok {
			hc.CloseWrite()
		} else {
			conn.Close()
		}
		halfClosed <- struct{}{}
		return err
	})

	errGroup.Go(func() error {
		_, err := io.Copy(c, conn)
		c.CloseWrite()
		halfClosed <- struct{}{}
		return err
	})

	return errGroup.Wait()
}

type HalfCloser interface {
	CloseWrite() error
}
