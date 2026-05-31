package udp

import (
	"context"
	"fmt"
	"kage/pkg/protocol/socks5"
	"kage/pkg/proxy/outbound"
	"log/slog"
	"net"
)

func Relay(ctx context.Context, inConn *net.UDPConn, ssOut *outbound.ShadowsocksUDP) error {
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
			
			dg := socks5.Datagram(buf[:n])
			if err := dg.Validate(); err != nil {
				slog.Warn("invalid socks5 datagram", "error", err)
				continue
			}
			
			payload, err := ssOut.Pack(addr, buf[3:n])
			if err != nil {
				slog.Error("failed to pack shadowsocks udp", "error", err)
				continue
			}
			
			if _, err := outConn.WriteToUDP(payload, ssOut.ServerAddr); err != nil {
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
