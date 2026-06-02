package socks5

import (
	"errors"
	"kage/core"
)

var (
	ErrInvalidDatagram = errors.New("socks5: invalid datagram")
)

type Datagram []byte

func (d Datagram) Validate() error {
	if len(d) < 4 {
		return ErrInvalidDatagram
	}
	if d[0] != 0x00 || d[1] != 0x00 {
		return ErrInvalidDatagram
	}
	if d[2] != 0x00 { // FRAG
		return errors.New("socks5: fragmentation not supported")
	}
	return nil
}

func (d Datagram) Address() (*core.Address, error) {
	return core.ReadAddressFromBytes(d[3:])
}

func (d Datagram) Payload() []byte {
	// Skip RSV(2), FRAG(1) and Address
	atyp := core.AddressType(d[3])
	offset := 4
	switch atyp {
	case core.AtypIPv4:
		offset += 4 + 2
	case core.AtypDomainName:
		domainLen := int(d[4])
		offset += 1 + domainLen + 2
	case core.AtypIPv6:
		offset += 16 + 2
	}
	return d[offset:]
}


func PackDatagram(addr *core.Address, payload []byte) []byte {
	addrBytes := addr.Bytes()
	buf := make([]byte, 3+len(addrBytes)+len(payload))
	buf[0] = 0x00
	buf[1] = 0x00
	buf[2] = 0x00 // FRAG
	copy(buf[3:], addrBytes)
	copy(buf[3+len(addrBytes):], payload)
	return buf
}

func ParseDatagram(b []byte) (addr *core.Address, payload []byte, err error) {
	d := Datagram(b)
	if err := d.Validate(); err != nil {
		return nil, nil, err
	}
	addr, err = d.Address()
	if err != nil {
		return nil, nil, err
	}
	return addr, d.Payload(), nil
}

