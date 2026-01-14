package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

var (
	ErrAddressTypeNotSupported = errors.New("socks5: address type not supported")
	ErrAddressLength           = errors.New("socks5: invalid address length")
)

type Atyp byte

const (
	AtypIPV4       Atyp = 1
	AtypDomainName Atyp = 3
	AtypIPV6       Atyp = 4
)

type Addr struct {
	ATYP Atyp
	Addr []byte
	Port uint16
}

func ReadAddrFrom(r io.Reader) (*Addr, error) {
	b := make([]byte, 1)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}

	atyp := Atyp(b[0])
	var addr []byte

	switch atyp {
	case AtypIPV4:
		addr = make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
	case AtypIPV6:
		addr = make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
	case AtypDomainName:
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		domainLen := int(b[0])
		addr = make([]byte, domainLen)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
	default:
		return nil, ErrAddressTypeNotSupported
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return nil, err
	}

	port := binary.BigEndian.Uint16(portBuf)

	return &Addr{
		ATYP: atyp,
		Addr: addr,
		Port: port,
	}, nil
}

func ParseAddrFromString(s string) (*Addr, error) {
	host, p, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}

	var addr []byte
	var atyp Atyp

	ip := net.ParseIP(host)
	if ip == nil {
		if len(host) > 0xFF {
			return nil, ErrAddressLength
		}
		addr = []byte(host)
		atyp = AtypDomainName
	} else if ipv4 := ip.To4(); ipv4 != nil {
		addr = ipv4
		atyp = AtypIPV4
	} else {
		addr = ip.To16()
		atyp = AtypIPV6
	}

	port, err := strconv.Atoi(p)
	if err != nil {
		return nil, err
	}
	return &Addr{
		ATYP: atyp,
		Addr: addr,
		Port: uint16(port),
	}, nil
}

func (a *Addr) Bytes() []byte {
	addrLen := len(a.Addr)
	if a.ATYP == AtypDomainName {
		addrLen += 1
	}

	buf := make([]byte, 1+addrLen+2)

	buf[0] = byte(a.ATYP)
	if a.ATYP == AtypDomainName {
		buf[1] = byte(len(a.Addr))
		copy(buf[2:], a.Addr)
	} else {
		copy(buf[1:], a.Addr)
	}

	binary.BigEndian.PutUint16(buf[1+addrLen:], a.Port)
	return buf
}

func (a *Addr) String() string {
	var host string
	switch a.ATYP {
	case AtypIPV4:
		host = net.IP(a.Addr).To4().String()
	case AtypDomainName:
		host = string(a.Addr)
	case AtypIPV6:
		host = net.IP(a.Addr).To16().String()
	default:
		return "unknown"
	}

	if a.Port == 443 {
		if a.ATYP == AtypIPV6 {
			return "https://[" + host + "]"
		}
		return "https://" + host
	} else if a.Port == 80 {
		if a.ATYP == AtypIPV6 {
			return "http://[" + host + "]"
		}
		return "http://" + host
	}

	return net.JoinHostPort(host, strconv.Itoa(int(a.Port)))
}
