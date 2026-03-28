package core

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

var (
	ErrAddressTypeNotSupported = errors.New("address: type not supported")
)

type AddressType byte

const (
	AtypIPV4       AddressType = 1
	AtypDomainName AddressType = 3
	AtypIPV6       AddressType = 4
)

type Address struct {
	Type AddressType
	Host []byte
	Port uint16
}

func (a *Address) Bytes() []byte {
	var host []byte
	switch a.Type {
	case AtypIPV4:
		host = a.Host
		if len(host) > 4 {
			host = host[len(host)-4:]
		}
	case AtypIPV6:
		host = a.Host
	case AtypDomainName:
		host = a.Host
	}
	
	addrLen := len(host)
	if a.Type == AtypDomainName {
		addrLen += 1
	}
	
	buf := make([]byte, 1+addrLen+2)
	buf[0] = byte(a.Type)
	
	if a.Type == AtypDomainName {
		buf[1] = byte(len(host))
		copy(buf[2:], host)
	} else {
		copy(buf[1:], host)
	}
	
	binary.BigEndian.PutUint16(buf[1+addrLen:], a.Port)
	return buf
}

func (a *Address) String() string {
	var host string
	switch a.Type {
	case AtypIPV4:
		host = net.IP(a.Host).To4().String()
	case AtypDomainName:
		host = string(a.Host)
	case AtypIPV6:
		host = net.IP(a.Host).To16().String()
	default:
		return "unknown"
	}
	return net.JoinHostPort(host, strconv.Itoa(int(a.Port)))
}

func ReadAddress(r io.Reader) (*Address, error) {
	b := make([]byte, 1)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	
	atyp := AddressType(b[0])
	var host []byte
	
	switch atyp {
	case AtypIPV4:
		host = make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, host); err != nil {
			return nil, err
		}
	case AtypIPV6:
		host = make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, host); err != nil {
			return nil, err
		}
	case AtypDomainName:
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		domainLen := int(b[0])
		host = make([]byte, domainLen)
		if _, err := io.ReadFull(r, host); err != nil {
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
	
	return &Address{
		Type: atyp,
		Host: host,
		Port: port,
	}, nil
}

func ParseAddress(s string) (*Address, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	
	var host []byte
	var atyp AddressType
	
	ip := net.ParseIP(h)
	if ip == nil {
		host = []byte(h)
		atyp = AtypDomainName
	} else if ipv4 := ip.To4(); ipv4 != nil {
		host = ipv4
		atyp = AtypIPV4
	} else {
		host = ip.To16()
		atyp = AtypIPV6
	}
	
	port, _ := strconv.Atoi(p)
	return &Address{
		Type: atyp,
		Host: host,
		Port: uint16(port),
	}, nil
}

func EmptyAddress() *Address {
	return &Address{
		Type: AtypIPV4,
		Host: []byte{0, 0, 0, 0},
		Port: 0,
	}
}
