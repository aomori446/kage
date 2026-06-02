package core

import (
	"context"
	"io"
	"net"
	
	"golang.org/x/sync/errgroup"
)

type HalfCloser interface {
	CloseWrite() error
}

func TCPRelay(ctx context.Context, client, server net.Conn) error {
	var errGroup errgroup.Group
	
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	
	halfClosed := make(chan struct{}, 2)
	defer close(halfClosed)
	go func() {
		<-halfClosed
		<-halfClosed
		cancel()
	}()
	
	errGroup.Go(func() error {
		<-ctx.Done()
		client.Close()
		server.Close()
		return ctx.Err()
	})
	
	// server → client
	errGroup.Go(func() error {
		_, err := io.Copy(client, server)
		if conn, ok := client.(HalfCloser); ok {
			conn.CloseWrite()
		} else {
			client.Close()
		}
		halfClosed <- struct{}{}
		return err
	})
	
	// client → server
	errGroup.Go(func() error {
		_, err := io.Copy(server, client)
		if conn, ok := server.(HalfCloser); ok {
			conn.CloseWrite()
		} else {
			server.Close()
		}
		halfClosed <- struct{}{}
		return err
	})
	
	return errGroup.Wait()
}
