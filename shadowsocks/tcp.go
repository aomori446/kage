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
	shadowConn *net.TCPConn

	enCipher *Cipher
	deCipher *Cipher

	buffer sync.Pool

	handshakePayload        []byte
	readServerHandshakeOnce sync.Once

	logger *slog.Logger
}

func NewShadowTCPConn(serverAddr *net.TCPAddr, key []byte, method config.CipherMethod, logger *slog.Logger) (*ShadowTCPConn, error) {
	shadowConn, err := net.DialTCP("tcp", nil, serverAddr)
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
		shadowConn: shadowConn,
		enCipher:   enCipher,
		logger:     logger,
		buffer: sync.Pool{
			New: func() any {
				buf := make([]byte, bufSize)
				return &buf
			},
		},
	}
	return stc, nil
}

func (stc *ShadowTCPConn) Read(p []byte) (n int, err error) {
	var handshakeErr error
	stc.readServerHandshakeOnce.Do(func() {
		handshakeErr = stc.readServerHandshake()
	})
	if handshakeErr != nil {
		return 0, handshakeErr
	}

	if len(stc.handshakePayload) > 0 {
		n = copy(p, stc.handshakePayload)
		stc.handshakePayload = stc.handshakePayload[n:]
		return n, nil
	}

	bufPtr := stc.buffer.Get().(*[]byte)
	defer stc.buffer.Put(bufPtr)
	buf := *bufPtr

	overhead := stc.enCipher.Overhead()
	n, err = io.ReadFull(stc.shadowConn, buf[:2+overhead])
	if err != nil {
		return n, err
	}

	lenChunk, err := stc.deCipher.Open(buf[:0], buf[:n])
	if err != nil {
		return 0, err
	}

	payloadSize := int(lenChunk[0])<<8 | int(lenChunk[1])
	if n, err = io.ReadFull(stc.shadowConn, buf[:payloadSize+overhead]); err != nil {
		return n, err
	}

	plaintext, err := stc.deCipher.Open(buf[:0], buf[:n])
	if err != nil {
		return 0, err
	}

	n = copy(p, plaintext)
	return n, nil
}

func (stc *ShadowTCPConn) Write(p []byte) (n int, err error) {
	bufPtr := stc.buffer.Get().(*[]byte)
	defer stc.buffer.Put(bufPtr)
	buf := *bufPtr

	lenBytes := []byte{byte(len(p) >> 8), byte(len(p))}
	buf = stc.enCipher.Seal(buf[:0], lenBytes)
	buf = stc.enCipher.Seal(buf, p)

	if _, err = stc.shadowConn.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (stc *ShadowTCPConn) Close() error {
	return stc.shadowConn.Close()
}

func (stc *ShadowTCPConn) Stream(ctx context.Context, conn net.Conn, targetAddr *socks5.Addr, initialPayload []byte) {
	defer stc.Close()
	defer conn.Close()

	if err := stc.writeClientHandshake(targetAddr, initialPayload); err != nil {
		stc.logger.Warn("write client handshake failed", "err", err)
	}

	stc.logger.Info("shadowsocks connection streaming started")

	errChan := make(chan error, 3)

	go func() {
		<-ctx.Done()
		_ = stc.Close()
		errChan <- ctx.Err()
	}()

	go func() {
		buf := make([]byte, MaxPayloadLength)
		_, err := io.CopyBuffer(conn, stc, buf)
		errChan <- err
	}()

	go func() {
		buf := make([]byte, MaxPayloadLength)
		_, err := io.CopyBuffer(stc, conn, buf)
		errChan <- err
	}()

	err := <-errChan
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		stc.logger.Debug("shadowsocks connection streaming closed with error", "err", err)
	}
	stc.logger.Info("shadowsocks connection streaming closed")
}

func (stc *ShadowTCPConn) writeClientHandshake(targetAddr *socks5.Addr, initialPayload []byte) error {
	vlh, err := newRequestVLH(targetAddr, initialPayload)
	if err != nil {
		return err
	}
	vlhBytes := vlh.Bytes()

	flh := newRequestFLH(vlhBytes)
	flhBytes := flh.Bytes()

	salt := append([]byte(nil), stc.enCipher.salt...)
	clientHandshake := stc.enCipher.Seals(salt, flhBytes, vlhBytes)

	_, err = stc.shadowConn.Write(clientHandshake)
	return err
}

func (stc *ShadowTCPConn) readServerHandshake() error {
	respSaltLen := len(stc.enCipher.salt)

	buf := make([]byte, respSaltLen+1+8+respSaltLen+2+stc.enCipher.Overhead())
	_, err := io.ReadFull(stc.shadowConn, buf)
	if err != nil {
		return err
	}

	respSalt := buf[:respSaltLen]
	deCipher, err := stc.enCipher.ReNew(respSalt)
	if err != nil {
		return err
	}
	stc.deCipher = deCipher

	encryptedFLH := buf[respSaltLen:]
	buf, err = deCipher.Open(nil, encryptedFLH)
	if err != nil {
		return err
	}

	flh, err := parseResponseFLH(buf, stc.enCipher.salt)
	if err != nil {
		return err
	}

	if flh.l > 0 {
		buf = make([]byte, int(flh.l)+deCipher.Overhead())
		_, err = io.ReadFull(stc.shadowConn, buf)
		if err != nil {
			return err
		}

		payload, err := deCipher.Open(buf[:0], buf)
		if err != nil {
			return err
		}
		stc.handshakePayload = payload
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

// ReadInitialPayload attempts to read the initial payload from the connection with a short timeout.
// It returns the data read (if any) and any error encountered (excluding timeout).
func ReadInitialPayload(conn net.Conn, timeout time.Duration) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
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
