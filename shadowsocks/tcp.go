package shadowsocks

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
	
	"github.com/aomori446/kage/config"
	"github.com/aomori446/kage/socks5"
)

type ShadowTCPConn struct {
	ctx  context.Context
	conn *net.TCPConn
	
	enCipher *Cipher
	deCipher *Cipher
	
	pool sync.Pool
	
	handshakePayload        []byte
	readServerHandshakeOnce sync.Once
	
	logger *slog.Logger
}

func NewShadowTCPConn(ctx context.Context, serverAddr *net.TCPAddr, key []byte, method config.CipherMethod, logger *slog.Logger) (*ShadowTCPConn, error) {
	serverConn, err := net.DialTCP("tcp", nil, serverAddr)
	if err != nil {
		return nil, err
	}
	
	salt, err := NewSalt(len(key))
	if err != nil {
		return nil, err
	}
	enCipher, err := NewCipher(key, salt, method)
	if err != nil {
		return nil, err
	}
	
	bufSize := 2 + enCipher.Overhead() + MaxPayloadLength + enCipher.Overhead()
	stc := &ShadowTCPConn{
		ctx:      ctx,
		conn:     serverConn,
		enCipher: enCipher,
		logger:   logger,
		pool: sync.Pool{
			New: func() any {
				buf := make([]byte, bufSize)
				return &buf
			},
		},
	}
	return stc, nil
}

func (c *ShadowTCPConn) Read(p []byte) (n int, err error) {
	var handshakeErr error
	c.readServerHandshakeOnce.Do(func() {
		handshakeErr = c.readServerHandshake()
	})
	if handshakeErr != nil {
		return 0, handshakeErr
	}
	
	if len(c.handshakePayload) > 0 {
		n = copy(p, c.handshakePayload)
		c.handshakePayload = c.handshakePayload[n:]
		return n, nil
	}
	
	bufPtr := c.pool.Get().(*[]byte)
	defer c.pool.Put(bufPtr)
	buf := *bufPtr
	
	overhead := c.enCipher.Overhead()
	n, err = io.ReadFull(c.conn, buf[:2+overhead])
	if err != nil {
		return n, err
	}
	
	lenChunk, err := c.deCipher.Open(buf[:0], buf[:n])
	if err != nil {
		return 0, err
	}
	
	payloadSize := int(lenChunk[0])<<8 | int(lenChunk[1])
	if n, err = io.ReadFull(c.conn, buf[:payloadSize+overhead]); err != nil {
		return n, err
	}
	
	plaintext, err := c.deCipher.Open(buf[:0], buf[:n])
	if err != nil {
		return 0, err
	}
	
	n = copy(p, plaintext)
	return n, nil
}

func (c *ShadowTCPConn) Write(p []byte) (n int, err error) {
	bufPtr := c.pool.Get().(*[]byte)
	defer c.pool.Put(bufPtr)
	buf := *bufPtr
	
	lenBytes := []byte{byte(len(p) >> 8), byte(len(p))}
	buf = c.enCipher.Seal(buf[:0], lenBytes)
	buf = c.enCipher.Seal(buf, p)
	
	if _, err = c.conn.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *ShadowTCPConn) Close() error {
	return c.conn.Close()
}

func (c *ShadowTCPConn) Stream(conn net.Conn, targetAddr *socks5.Addr, initialPayload []byte) {
	defer c.Close()
	defer conn.Close()
	
	if err := c.writeClientHandshake(targetAddr, initialPayload); err != nil {
		c.logger.Warn("write client handshake failed", "err", err)
	}
	
	c.logger.Info("shadowsocks connection streaming started")
	
	errChan := make(chan error, 3)
	
	go func() {
		<-c.ctx.Done()
		_ = c.Close()
		errChan <- c.ctx.Err()
	}()
	
	go func() {
		buf := make([]byte, MaxPayloadLength)
		_, err := io.CopyBuffer(conn, c, buf)
		errChan <- err
	}()
	
	go func() {
		buf := make([]byte, MaxPayloadLength)
		_, err := io.CopyBuffer(c, conn, buf)
		errChan <- err
	}()
	
	err := <-errChan
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		c.logger.Debug("shadowsocks connection streaming closed with error", "err", err)
	}
	c.logger.Info("shadowsocks connection streaming closed")
}

func (c *ShadowTCPConn) writeClientHandshake(targetAddr *socks5.Addr, initialPayload []byte) error {
	vlh, err := newRequestVLH(targetAddr, initialPayload)
	if err != nil {
		return err
	}
	vlhBytes := vlh.Bytes()
	
	flh := newRequestFLH(vlhBytes)
	flhBytes := flh.Bytes()
	
	salt := append([]byte(nil), c.enCipher.salt...)
	clientHandshake := c.enCipher.Seals(salt, flhBytes, vlhBytes)
	
	_, err = c.conn.Write(clientHandshake)
	return err
}

func (c *ShadowTCPConn) readServerHandshake() error {
	respSaltLen := len(c.enCipher.salt)
	
	buf := make([]byte, respSaltLen+1+8+respSaltLen+2+c.enCipher.Overhead())
	_, err := io.ReadFull(c.conn, buf)
	if err != nil {
		return err
	}
	
	respSalt := buf[:respSaltLen]
	deCipher, err := c.enCipher.ReNew(respSalt)
	if err != nil {
		return err
	}
	c.deCipher = deCipher
	
	encryptedFLH := buf[respSaltLen:]
	buf, err = deCipher.Open(nil, encryptedFLH)
	if err != nil {
		return err
	}
	
	flh, err := parseResponseFLH(buf, c.enCipher.salt)
	if err != nil {
		return err
	}
	
	if flh.l > 0 {
		buf = make([]byte, int(flh.l)+deCipher.Overhead())
		_, err = io.ReadFull(c.conn, buf)
		if err != nil {
			return err
		}
		
		payload, err := deCipher.Open(buf[:0], buf)
		if err != nil {
			return err
		}
		c.handshakePayload = payload
	}
	
	return nil
}

type requestVLH struct {
	addr           *socks5.Addr
	padding        []byte
	initialPayload []byte
}

func newRequestVLH(addr *socks5.Addr, initialPayload []byte) (*requestVLH, error) {
	padding, err := Padding(1, MaxPaddingLength)
	if err != nil {
		return nil, err
	}
	return &requestVLH{
		addr:           addr,
		padding:        padding,
		initialPayload: initialPayload,
	}, nil
}

func (v *requestVLH) Bytes() []byte {
	return append(v.addr.Bytes(), append(v.padding, v.initialPayload...)...)
}

type requestFLH struct {
	ht        HeaderTypeStream
	timeStamp time.Time
	l         uint16
}

func newRequestFLH(vlh []byte) *requestFLH {
	return &requestFLH{
		ht:        HeaderTypeClientStream,
		timeStamp: time.Now(),
		l:         uint16(len(vlh)),
	}
}

func (f *requestFLH) Bytes() []byte {
	flh := make([]byte, 0, 11)
	flh = append(flh, byte(f.ht))
	flh = binary.BigEndian.AppendUint64(flh, uint64(f.timeStamp.Unix()))
	flh = binary.BigEndian.AppendUint16(flh, f.l)
	return flh
}

type responseFLH struct {
	ht          HeaderTypeStream
	timeStamp   time.Time
	requestSalt []byte
	l           uint16
	
	originSalt []byte
}

func parseResponseFLH(data, salt []byte) (*responseFLH, error) {
	ht := HeaderTypeStream(data[0])
	timestamp := time.Unix(int64(binary.BigEndian.Uint64(data[1:9])), 0)
	requestSalt := data[9 : 9+len(salt)]
	l := binary.BigEndian.Uint16(data[9+len(salt):])
	
	flh := &responseFLH{
		ht:          ht,
		timeStamp:   timestamp,
		requestSalt: requestSalt,
		l:           l,
		originSalt:  salt,
	}
	
	if err := flh.validate(); err != nil {
		return nil, err
	}
	
	return flh, nil
}

func (f *responseFLH) validate() error {
	if f.ht != HeaderTypeServerStream {
		return ErrHeaderType
	}
	
	if time.Since(f.timeStamp).Seconds() > 30 {
		return errors.New("timestamp skewed")
	}
	
	if !bytes.Equal(f.requestSalt, f.originSalt) {
		return errors.New("request Salt mismatched")
	}
	
	return nil
}

func WaitForInitialPayload(conn net.Conn) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		return nil, err
	}
	defer conn.SetReadDeadline(time.Time{})
	
	buf := make([]byte, MaxInitialPayloadLength)
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
