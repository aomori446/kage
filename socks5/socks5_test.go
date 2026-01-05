package socks5

import (
	"bytes"
	"net"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestCommand_Validate(t *testing.T) {
	type args struct {
		cmd Command
	}
	tests := []struct {
		name      string
		c         Command
		args      args
		wantReply []byte
		wantErr   bool
	}{
		{
			name: "Command.Validate(same Command)",
			c:    Connect,
			args: args{
				cmd: Connect,
			},
			wantReply: make([]byte, 0),
			wantErr:   false,
		},
		{
			name: "Command.Validate(different Command)",
			c:    Connect,
			args: args{
				cmd: Bind,
			},
			wantReply: func() []byte {
				addr := &Addr{
					ATYP: AtypIPV4,
					Addr: net.IPv4(0, 0, 0, 0).To4(),
					Port: 0,
				}
				return append([]byte{
					byte(Version),
					byte(CommandNotSupported),
					byte(0x00),
				}, addr.Bytes()...)
			}(),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			err := tt.c.Validate(tt.args.cmd, buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotReply := buf.Bytes(); !slices.Equal(gotReply, tt.wantReply) {
				t.Errorf("Validate() gotReply = %v, cmd %v", gotReply, tt.wantReply)
			}
		})
	}
}

func TestTCPHandShake(t *testing.T) {
	tests := []struct {
		name    string
		prepare func() (net.Conn, func())
		timeout time.Duration
		wantReq *TCPRequest
		wantErr bool
	}{
		{
			name: "normal_socks5_handshake_without_timeout",
			prepare: func() (net.Conn, func()) {
				server, client := net.Pipe()
				go func() {
					defer client.Close()

					_, err := client.Write([]byte{
						byte(Version),
						byte(1),
						byte(NoAuthenticationRequired),
					})
					if err != nil {
						panic(err)
					}

					_, err = client.Read(make([]byte, 2))
					if err != nil {
						panic(err)
					}

					addr := &Addr{
						ATYP: AtypIPV4,
						Addr: net.IPv4(127, 0, 0, 1).To4(),
						Port: 8080,
					}

					_, err = client.Write(
						append([]byte{
							byte(Version),
							byte(Connect),
							byte(0x00),
						}, addr.Bytes()...),
					)
					if err != nil {
						panic(err)
					}
				}()

				return server, func() { server.Close() }
			},
			timeout: time.Second,
			wantReq: &TCPRequest{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, cleanup := tt.prepare()
			defer cleanup()

			gotReq, err := TCPHandShake(conn, tt.timeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("TCPHandShake() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotReq, tt.wantReq) {
				t.Errorf("TCPHandShake() gotReq = %v, cmd %v", gotReq, tt.wantReq)
			}
		})
	}
}
