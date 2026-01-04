package shadowsocks

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aomori446/kage/config"
	"github.com/aomori446/kage/handler"
)

type Relayer struct {
	sessionMap sync.Map // map[clientAddr string]*Session

	ln          net.PacketConn
	blockCipher cipher.Block

	ph handler.UDPPacketHandler

	key        []byte
	method     config.CipherMethod
	logger     *slog.Logger
	listenAddr *net.UDPAddr
	serverAddr *net.UDPAddr
}

func NewRelayer(
	key []byte,
	method config.CipherMethod,
	listenAddr *net.UDPAddr,
	serverAddr *net.UDPAddr,
	ph handler.UDPPacketHandler,
	logger *slog.Logger,
) (*Relayer, error) {
	ln, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}

	return &Relayer{
		key:        key,
		method:     method,
		logger:     logger,
		listenAddr: listenAddr,
		serverAddr: serverAddr,
		ph:         ph,

		ln:          ln,
		blockCipher: blockCipher,
	}, nil
}

func (r *Relayer) Relay(ctx context.Context) error {
	defer r.Close()
	go func() {
		<-ctx.Done()
		_ = r.Close()
	}()

	go r.monitorSessions(ctx)

	r.logger = r.logger.With("listenAddr", r.listenAddr.String(), "serverAddr", r.serverAddr.String())
	r.logger.Debug("UDP relayer started")

	buf := make([]byte, MaxUDPPacketLen)
	for {
		n, clientAddr, err := r.ln.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			if errors.Is(err, net.ErrClosed) {
				return nil
			}

			r.logger.Warn("read from client failed", "err", err)
			continue
		}

		s, err := r.loadOrStoreSession(clientAddr)
		if err != nil {
			r.logger.Error("load session failed", "err", err, "clientAddr", clientAddr.String())
			continue
		}

		if err = s.wrapAndWrite(buf[:n]); err != nil {
			r.logger.Warn("write to server failed", "err", err, "clientAddr", clientAddr.String())
			_ = s.Close()
			r.sessionMap.Delete(clientAddr.String())
		}
	}
}

func (r *Relayer) monitorSessions(ctx context.Context) {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().Unix()
			timeout := int64(SessionTimeout.Seconds())

			r.sessionMap.Range(func(key, value interface{}) bool {
				s := value.(*Session)
				lastActive := atomic.LoadInt64(&s.lastActive)

				if now-lastActive > timeout {
					r.logger.Debug("close session due to timeout", "clientAddr", key)
					_ = s.Close()
					r.sessionMap.Delete(key)
				}
				return true
			})
		}
	}
}

func (r *Relayer) loadOrStoreSession(clientAddr net.Addr) (*Session, error) {
	k := clientAddr.String()
	if v, ok := r.sessionMap.Load(k); ok {
		return v.(*Session), nil
	}

	salt, err := NewSalt(8)
	if err != nil {
		return nil, err
	}
	enCipher, err := NewCipher(r.key, salt, r.method)
	if err != nil {
		return nil, err
	}
	s, err := NewSession(r, clientAddr, enCipher)
	if err != nil {
		return nil, err
	}

	if v, ok := r.sessionMap.LoadOrStore(k, s); ok {
		_ = s.Close()
		return v.(*Session), nil
	}

	return s, nil
}

func (r *Relayer) Close() error {
	if r.ln != nil {
		if err := r.ln.Close(); err != nil {
			return err
		}
	}

	r.sessionMap.Range(func(key, value interface{}) bool {
		s := value.(*Session)
		_ = s.Close()
		return true
	})

	return nil
}

type Session struct {
	r          *Relayer
	clientAddr net.Addr
	enCipher   *Cipher
	deCipher   *Cipher

	serverConn *net.UDPConn
	lastActive int64
}

func NewSession(r *Relayer, clientAddr net.Addr, enCipher *Cipher) (*Session, error) {
	serverConn, err := net.DialUDP("udp", nil, r.serverAddr)
	if err != nil {
		return nil, err
	}
	s := &Session{
		r:          r,
		clientAddr: clientAddr,
		enCipher:   enCipher,
		serverConn: serverConn,
		lastActive: time.Now().Unix(),
	}
	go s.relayFromServer()
	return s, nil
}

func (s *Session) updateActivity() {
	atomic.StoreInt64(&s.lastActive, time.Now().Unix())
}

func (s *Session) Close() error {
	if s.serverConn != nil {
		return s.serverConn.Close()
	}
	return nil
}

func (s *Session) relayFromServer() {
	defer func() {
		_ = s.Close()
		s.r.sessionMap.Delete(s.clientAddr.String())
	}()

	buf := make([]byte, MaxUDPPacketLen)
	for {
		n, err := s.serverConn.Read(buf)
		if err != nil {
			return
		}

		decryptedSSPayload, err := unwrap(buf[:n], s.enCipher, s.deCipher, s.r.blockCipher)
		if err != nil {
			s.r.logger.Warn("unwrap data from server failed", "err", err)
			return
		}

		clientPacket, err := s.r.ph.HandleOutbound(decryptedSSPayload)
		if err != nil {
			s.r.logger.Warn("handle outbound packet failed", "err", err)
			return
		}

		_, err = s.r.ln.WriteTo(clientPacket, s.clientAddr)
		if err != nil {
			s.r.logger.Debug("write back to client failed", "err", err)
			return
		}

		s.updateActivity()
	}
}

func (s *Session) wrapAndWrite(packet []byte) error {
	ssPayload, err := s.r.ph.HandleInbound(packet)
	if err != nil {
		return err
	}

	wrappedData, err := wrap(ssPayload, s.enCipher, s.r.blockCipher)
	if err != nil {
		return err
	}

	_, err = s.serverConn.Write(wrappedData)
	if err != nil {
		return err
	}

	s.updateActivity()
	return nil
}

func wrap(data []byte, enCipher *Cipher, blockCipher cipher.Block) ([]byte, error) {
	separateHeader := buildSeparateHeader(enCipher)
	encryptedSeparateHeader := make([]byte, 16)
	blockCipher.Encrypt(encryptedSeparateHeader, separateHeader)

	msg, err := buildClientMessage(data)
	if err != nil {
		return nil, err
	}

	encryptedMsg := enCipher.SealWithNonce(nil, separateHeader[4:16], msg)
	return append(encryptedSeparateHeader, encryptedMsg...), nil
}

func buildSeparateHeader(enCipher *Cipher) []byte {
	header := make([]byte, 16)
	copy(header[0:8], enCipher.Salt())
	copy(header[8:16], enCipher.Nonce())
	return header
}

func buildClientMessage(payload []byte) ([]byte, error) {
	header := make([]byte, 0, 100)
	header = append(header, byte(HeaderTypeClientPacket))                     // Type
	header = binary.BigEndian.AppendUint64(header, uint64(time.Now().Unix())) // Timestamp

	padding, err := Padding(1, 100)
	if err != nil {
		return nil, err
	}
	header = binary.BigEndian.AppendUint16(header, uint16(len(padding)))
	header = append(header, padding...)

	message := append(header, payload...)
	return message, nil
}

func unwrap(data []byte, enCipher *Cipher, deCipher *Cipher, blockCipher cipher.Block) ([]byte, error) {
	encryptedHeader := data[:16]
	separateHeader := make([]byte, 16)
	blockCipher.Decrypt(separateHeader, encryptedHeader)

	if deCipher == nil {
		var err error
		serverSessionID := separateHeader[:8]
		deCipher, err = enCipher.ReNew(serverSessionID)
		if err != nil {
			return nil, err
		}
	}

	nonce := separateHeader[4:16]
	msg, err := deCipher.OpenWithNonce(nil, nonce, data[16:])
	if err != nil {
		return nil, err
	}

	return parseServerMessage(msg, enCipher)
}

func parseServerMessage(data []byte, enCipher *Cipher) ([]byte, error) {
	if len(data) < 19 {
		return nil, errors.New("server message too short")
	}

	if data[0] != byte(HeaderTypeServerPacket) {
		return nil, ErrHeaderType
	}

	timestamp := binary.BigEndian.Uint64(data[1:9])
	ts := time.Unix(int64(timestamp), 0)
	if time.Since(ts).Abs().Seconds() > 30 {
		return nil, errors.New("timestamp skewed")
	}

	clientSessionID := data[9:17]
	if !bytes.Equal(clientSessionID, enCipher.Salt()) {
		return nil, errors.New("client session ID mismatch")
	}

	paddingLen := binary.BigEndian.Uint16(data[17:19])
	if len(data) < 19+int(paddingLen) {
		return nil, errors.New("invalid padding length")
	}

	addrStart := 19 + int(paddingLen)
	data = data[addrStart:]

	// [ATYP][ADDR][PORT][DATA]
	return data, nil
}
