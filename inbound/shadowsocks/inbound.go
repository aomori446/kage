package shadowsocks

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/aomori446/kage/core"
	"github.com/aomori446/kage/outbound"
	"github.com/aomori446/kage/outbound/shadowsocks"
)

type Inbound struct {
	Outbound   outbound.Outbound
	ListenAddr string
	Method     string
	Key        []byte
}

func (c *Inbound) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", c.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s failed: %w", c.ListenAddr, err)
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	slog.Info("Shadowsocks inbound listening", "addr", c.ListenAddr)

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				err = fmt.Errorf("accept new connection failed: %w", err)
			} else {
				err = nil
			}
			return err
		}

		go c.handleConn(ctx, clientConn)
	}
}

func (c *Inbound) handleConn(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	saltSize := getSaltSize(c.Method)
	if saltSize == 0 {
		slog.Error("Unsupported method in Shadowsocks inbound", "method", c.Method)
		return
	}

	// 1. Read Client Salt
	clientSalt := make([]byte, saltSize)
	if _, err := io.ReadFull(clientConn, clientSalt); err != nil {
		slog.Debug("[Shadowsocks] failed to read client salt", "err", err)
		return
	}

	// 2. Read and Decrypt Client Fixed-length Header
	clientFlBuf := make([]byte, 27)
	if _, err := io.ReadFull(clientConn, clientFlBuf); err != nil {
		slog.Debug("[Shadowsocks] failed to read client flHeader", "err", err)
		return
	}

	deCipher, err := shadowsocks.NewCipherWithSalt(c.Method, c.Key, clientSalt)
	if err != nil {
		slog.Error("[Shadowsocks] failed to create decrypt cipher", "err", err)
		return
	}

	flHeader, err := deCipher.Open(nil, clientFlBuf)
	if err != nil {
		slog.Debug("[Shadowsocks] failed to decrypt flHeader", "err", err)
		return
	}

	if flHeader[0] != 0 {
		slog.Debug("[Shadowsocks] invalid type in flHeader", "type", flHeader[0])
		return
	}

	clientTime := time.Unix(int64(binary.BigEndian.Uint64(flHeader[1:9])), 0)
	if time.Since(clientTime) > 30*time.Second || time.Since(clientTime) < -30*time.Second {
		slog.Debug("[Shadowsocks] request timestamp expired", "time", clientTime)
		return
	}

	vlLen := binary.BigEndian.Uint16(flHeader[9:11])

	// 3. Read and Decrypt Client Variable-length Header
	clientVlBuf := make([]byte, int(vlLen)+16)
	if _, err := io.ReadFull(clientConn, clientVlBuf); err != nil {
		slog.Debug("[Shadowsocks] failed to read client vlHeader", "err", err)
		return
	}

	vlHeader, err := deCipher.Open(nil, clientVlBuf)
	if err != nil {
		slog.Debug("[Shadowsocks] failed to decrypt vlHeader", "err", err)
		return
	}

	addrLen := getAddrLen(vlHeader)
	if addrLen == 0 || len(vlHeader) < addrLen {
		slog.Debug("[Shadowsocks] invalid address in vlHeader")
		return
	}

	targetAddr, err := core.ReadAddressFromBytes(vlHeader[:addrLen])
	if err != nil {
		slog.Debug("[Shadowsocks] failed to parse target address", "err", err)
		return
	}

	paddingLen := int(binary.BigEndian.Uint16(vlHeader[addrLen : addrLen+2]))
	if len(vlHeader) < addrLen+2+paddingLen {
		slog.Debug("[Shadowsocks] invalid padding in vlHeader")
		return
	}
	initialPayload := vlHeader[addrLen+2+paddingLen:]

	// 4. Dial Outbound
	outConn, err := c.Outbound.Dial(ctx, targetAddr)
	if err != nil {
		slog.Error("[Shadowsocks] failed to dial outbound", "target", targetAddr, "err", err)
		return
	}
	defer outConn.Close()

	if len(initialPayload) > 0 {
		if _, err := outConn.Write(initialPayload); err != nil {
			slog.Debug("[Shadowsocks] failed to write initial payload", "err", err)
			return
		}
	}

	// 5. Send Server Response Header
	serverSalt := make([]byte, saltSize)
	if _, err := rand.Read(serverSalt); err != nil {
		slog.Error("[Shadowsocks] failed to generate server salt", "err", err)
		return
	}

	enCipher, err := shadowsocks.NewCipherWithSalt(c.Method, c.Key, serverSalt)
	if err != nil {
		slog.Error("[Shadowsocks] failed to create encrypt cipher", "err", err)
		return
	}

	serverFlHeader := make([]byte, 0, 11+saltSize)
	serverFlHeader = append(serverFlHeader, 1)
	serverFlHeader = binary.BigEndian.AppendUint64(serverFlHeader, uint64(time.Now().Unix()))
	serverFlHeader = append(serverFlHeader, clientSalt...)
	serverFlHeader = binary.BigEndian.AppendUint16(serverFlHeader, 0)

	respBuf := append([]byte(nil), serverSalt...)
	respBuf = enCipher.Seal(respBuf, serverFlHeader)
	respBuf = enCipher.Seal(respBuf, nil)

	if _, err := clientConn.Write(respBuf); err != nil {
		slog.Debug("[Shadowsocks] failed to write server response header", "err", err)
		return
	}

	// 6. Wrap Client Connection with Crypt Wrapper
	cryptoConn := &CryptoConn{
		Conn:     clientConn,
		enCipher: enCipher,
		deCipher: deCipher,
	}

	slog.Debug("[Shadowsocks] connection established", "client", clientConn.RemoteAddr(), "target", targetAddr)

	if err = core.Relay(ctx, cryptoConn, outConn); err != nil {
		slog.Debug("[Shadowsocks] relay error", "client", clientConn.RemoteAddr(), "err", err)
	}
}

type CryptoConn struct {
	net.Conn
	enCipher   *shadowsocks.Cipher
	deCipher   *shadowsocks.Cipher
	readBuffer []byte
}

func (c *CryptoConn) Write(p []byte) (int, error) {
	const maxChunkSize = 16383
	written := 0
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > maxChunkSize {
			chunkSize = maxChunkSize
		}
		chunk := p[:chunkSize]
		p = p[chunkSize:]

		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(chunkSize))

		buf := c.enCipher.Seal(nil, lenBuf)
		buf = c.enCipher.Seal(buf, chunk)

		_, err := c.Conn.Write(buf)
		if err != nil {
			return written, err
		}
		written += chunkSize
	}
	return written, nil
}

func (c *CryptoConn) Read(p []byte) (int, error) {
	if len(c.readBuffer) > 0 {
		n := copy(p, c.readBuffer)
		c.readBuffer = c.readBuffer[n:]
		return n, nil
	}

	chunkHeader := make([]byte, 18)
	if _, err := io.ReadFull(c.Conn, chunkHeader); err != nil {
		return 0, err
	}

	lenBuf, err := c.deCipher.Open(nil, chunkHeader)
	if err != nil {
		return 0, err
	}

	payloadLen := binary.BigEndian.Uint16(lenBuf)
	payloadBuf := make([]byte, int(payloadLen)+16)
	if _, err := io.ReadFull(c.Conn, payloadBuf); err != nil {
		return 0, err
	}

	payload, err := c.deCipher.Open(nil, payloadBuf)
	if err != nil {
		return 0, err
	}

	n := copy(p, payload)
	if n < len(payload) {
		c.readBuffer = append(c.readBuffer, payload[n:]...)
	}
	return n, nil
}

func getSaltSize(method string) int {
	switch method {
	case "2022-blake3-aes-128-gcm":
		return 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32
	default:
		return 0
	}
}

func getAddrLen(b []byte) int {
	if len(b) < 1 {
		return 0
	}
	atyp := core.AddressType(b[0])
	switch atyp {
	case core.AtypIPv4:
		return 1 + net.IPv4len + 2
	case core.AtypIPv6:
		return 1 + net.IPv6len + 2
	case core.AtypDomainName:
		if len(b) < 2 {
			return 0
		}
		domainLen := int(b[1])
		return 1 + 1 + domainLen + 2
	default:
		return 0
	}
}
