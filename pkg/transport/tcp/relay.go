package tcp

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
)

type HalfCloser interface {
	CloseWrite() error
}

func Relay(ctx context.Context, client, remote net.Conn) {
	clientAddr := client.RemoteAddr()
	remoteAddr := remote.RemoteAddr()
	slog.Debug("relay started", "client", clientAddr, "remote", remoteAddr)
	
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
	
	slog.Debug("relay finished", "client", clientAddr, "remote", remoteAddr,
		"uploaded bytes", uploaded, "downloaded bytes", downloaded,
		"upload err", upErr, "download err", downErr)
}
