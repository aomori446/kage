package socks5

import (
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"time"
)

const (
	Version = 0x05
)

var (
	ErrHandshake = func(err error) error { return fmt.Errorf("handshake failed: %w", err) }
	
	ErrVersionNotSupported = errors.New("socks5: version not supported")
	ErrCommandNotSupported = errors.New("socks5: command not supported")
	ErrMethodsCount        = errors.New("socks5: invalid methods count")
	ErrNoAcceptableMethods = errors.New("socks5: no acceptable methods")
)

const (
	Connect      Command = 0x01
	Bind         Command = 0x02
	UDPAssociate Command = 0x03
)

type Command byte

func (c Command) Validate(cmd Command, conn io.Writer) error {
	if c != cmd {
		resp := TCPResponse{
			Filed: CommandNotSupported,
			Addr: &Addr{
				ATYP: AtypIPV4,
				Addr: net.IPv4(0, 0, 0, 0).To4(),
				Port: 0,
			},
		}
		_ = resp.ReplyTo(conn)
		return ErrCommandNotSupported
	}
	return nil
}

const (
	NoAuthenticationRequired Method = 0x00
	GSSAPI                   Method = 0x01
	UsernamePassword         Method = 0x02
	NoAcceptableMethods      Method = 0xFF
)

type Method byte

//+----+-----+-------+------+----------+----------+
//|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//+----+-----+-------+------+----------+----------+
//| 1  |  1  | X'00' |  1   | Variable |    2     |
//+----+-----+-------+------+----------+----------+

type TCPRequest struct {
	Command Command
	Addr    *Addr
}

func TCPHandShake(conn net.Conn, timeout time.Duration) (req *TCPRequest, err error) {
	defer func() {
		if err != nil {
			err = ErrHandshake(err)
		}
	}()
	
	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return
	}
	defer conn.SetDeadline(time.Time{})
	
	//+----+----------+----------+
	//|VER | NMETHODS | METHODS  |
	//+----+----------+----------+
	//| 1  |    1     | 1 to 255 |
	//+----+----------+----------+
	buf := make([]byte, 255)
	_, err = io.ReadFull(conn, buf[:2])
	if err != nil {
		return nil, err
	}
	
	v := buf[0]
	if v != Version {
		return nil, ErrVersionNotSupported
	}
	
	nMethods := int(buf[1])
	if nMethods < 1 {
		return nil, ErrMethodsCount
	}
	
	_, err = io.ReadFull(conn, buf[:nMethods])
	if err != nil {
		return nil, err
	}
	
	if !slices.Contains(buf[:nMethods], byte(NoAuthenticationRequired)) {
		conn.Write([]byte{byte(Version), byte(NoAcceptableMethods)})
		return nil, ErrNoAcceptableMethods
	}
	
	//+----+--------+
	//|VER | METHOD |
	//+----+--------+
	//| 1  |   1    |
	//+----+--------+
	if _, err = conn.Write([]byte{byte(Version), byte(NoAuthenticationRequired)}); err != nil {
		return nil, err
	}
	
	_, err = io.ReadFull(conn, buf[:3]) // VER + CMD + RSV
	if err != nil {
		return nil, err
	}
	
	cmd := Command(buf[1])
	
	addr, err := ReadAddrFrom(conn)
	if err != nil {
		return nil, err
	}
	
	req = &TCPRequest{
		Command: cmd,
		Addr:    addr,
	}
	
	return req, nil
}

type ReplyFiled byte

//+----+-----+-------+------+----------+----------+
//|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//+----+-----+-------+------+----------+----------+
//| 1  |  1  | X'00' |  1   | Variable |    2     |
//+----+-----+-------+------+----------+----------+

const (
	Success             ReplyFiled = 0x00
	CommandNotSupported ReplyFiled = 0x07
)

type TCPResponse struct {
	Filed ReplyFiled
	Addr  *Addr
}

func (r *TCPResponse) Bytes() []byte {
	return append(
		[]byte{
			byte(Version),
			byte(r.Filed),
			byte(0x00),
		},
		r.Addr.Bytes()...,
	)
}

func (r *TCPResponse) ReplyTo(conn io.Writer) error {
	_, err := conn.Write(r.Bytes())
	return err
}

func NewSuccessTCPResponse() *TCPResponse {
	return &TCPResponse{
		Filed: Success,
		Addr: &Addr{
			ATYP: AtypIPV4,
			Addr: net.IPv4(0, 0, 0, 0).To4(),
			Port: 0,
		},
	}
}
