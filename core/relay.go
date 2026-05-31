package core

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
)

type HalfCloser interface {
	CloseWrite() error
}

func TCPRelay(ctx context.Context, client, remote net.Conn) {
	clientAddr := client.RemoteAddr()
	remoteAddr := remote.RemoteAddr()
	slog.Debug("tcp relay started", "client", clientAddr, "remote", remoteAddr)
	
	go func() {
		<-ctx.Done()
		client.Close()
		remote.Close()
	}()
	
	var wg sync.WaitGroup
	wg.Add(2)
	
	var uploaded, downloaded int64
	var upErr, downErr error
	
	go func() {
		defer wg.Done()
		downloaded, downErr = io.Copy(client, remote)
		if conn, ok := client.(HalfCloser); ok {
			conn.CloseWrite()
		}
	}()
	
	go func() {
		defer wg.Done()
		uploaded, upErr = io.Copy(remote, client)
		if conn, ok := remote.(HalfCloser); ok {
			conn.CloseWrite()
		}
	}()
	
	wg.Wait()
	
	slog.Debug("tcp relay finished", "client", clientAddr, "remote", remoteAddr,
		"uploaded bytes", uploaded, "downloaded bytes", downloaded,
		"upload err", upErr, "download err", downErr)
}

type UDPOutbound interface {
	Pack(clientAddr *net.UDPAddr, data []byte) ([]byte, error)
	Unpack(payload []byte) ([]byte, *net.UDPAddr, error)
	GetServerAddr() *net.UDPAddr
}

type SOCKS5UDPDatagram interface {
	Validate() error
	Payload() []byte
}

func UDPRelay(ctx context.Context, inConn *net.UDPConn, ssOut UDPOutbound) error {
	outConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return fmt.Errorf("failed to listen on udp for outbound: %w", err)
	}
	defer outConn.Close()
	
	errCh := make(chan error, 2)
	
	// Client to Server
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			n, addr, err := inConn.ReadFromUDP(buf)
			if err != nil {
				errCh <- err
				return
			}
			
			if n < 4 || buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00 {
                slog.Warn("invalid socks5 datagram from client", "addr", addr)
                continue
            }
            
			payload, err := ssOut.Pack(addr, buf[3:n])
			if err != nil {
				slog.Error("failed to pack shadowsocks udp", "error", err)
				continue
			}
			
			if _, err := outConn.WriteToUDP(payload, ssOut.GetServerAddr()); err != nil {
				errCh <- err
				return
			}
		}
	}()
	
	// Server to Client
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			n, _, err := outConn.ReadFromUDP(buf)
			if err != nil {
				errCh <- err
				return
			}
			
			data, clientAddr, err := ssOut.Unpack(buf[:n])
			if err != nil {
				slog.Warn("failed to unpack shadowsocks udp", "error", err)
				continue
			}
			
			dg := make([]byte, 3+len(data))
			dg[0] = 0x00
			dg[1] = 0x00
			dg[2] = 0x00
			copy(dg[3:], data)
			
			if _, err := inConn.WriteToUDP(dg, clientAddr); err != nil {
				errCh <- err
				return
			}
		}
	}()
	
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}
