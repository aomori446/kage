package socks5

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"testing"
)

func TestReadAddrFrom(t *testing.T) {
	type args struct {
		r io.Reader
	}
	tests := []struct {
		name    string
		args    args
		want    *Addr
		wantErr bool
	}{
		{
			name: "valid ipv4 address",
			args: args{
				r: bytes.NewReader(func() []byte {
					atyp := []byte{byte(AtypIPV4)}
					addr := net.IPv4(127, 0, 0, 1).To4()
					port := make([]byte, 2)
					binary.BigEndian.PutUint16(port, uint16(1234))
					return append(atyp, append(addr, port...)...)
				}()),
			},
			want: &Addr{
				ATYP: AtypIPV4,
				Addr: net.IPv4(127, 0, 0, 1).To4(),
				Port: 1234,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadAddrFrom(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadAddrFrom() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReadAddrFrom() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseAddrFromString(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    *Addr
		wantErr bool
	}{
		{
			name: "valid ipv4",
			args: args{
				s: "127.0.0.1:8080",
			},
			want: &Addr{
				ATYP: AtypIPV4,
				Addr: net.IPv4(127, 0, 0, 1).To4(),
				Port: 8080,
			},
			wantErr: false,
		},
		{
			name: "valid ipv6",
			args: args{
				s: "[::1]:8080",
			},
			want: &Addr{
				ATYP: AtypIPV6,
				Addr: net.IPv6loopback,
				Port: 8080,
			},
			wantErr: false,
		},
		{
			name: "valid domainname",
			args: args{
				s: "example.org:8080",
			},
			want: &Addr{
				ATYP: AtypDomainName,
				Addr: []byte("example.org"),
				Port: 8080,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAddrFromString(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAddrFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseAddrFromString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddr_Bytes(t *testing.T) {
	type fields struct {
		ATYP Atyp
		Addr []byte
		Port uint16
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{
			name: "127.0.0.1:8080",
			fields: fields{
				ATYP: AtypIPV4,
				Addr: []byte{
					127, 0, 0, 1,
				},
				Port: 8080,
			},
			want: func() []byte {
				buf := make([]byte, 0, 1+net.IPv4len+2)

				buf = append(buf, byte(AtypIPV4))

				buf = append(buf, net.IPv4(127, 0, 0, 1).To4()...)

				p := make([]byte, 2)
				binary.BigEndian.PutUint16(p, uint16(8080))

				buf = append(buf, p...)

				return buf
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Addr{
				ATYP: tt.fields.ATYP,
				Addr: tt.fields.Addr,
				Port: tt.fields.Port,
			}
			if got := a.Bytes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Bytes() = %v, want %v", got, tt.want)
			}
		})
	}
}
