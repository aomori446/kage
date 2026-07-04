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

func Relay(ctx context.Context, left, right net.Conn) error {
	var errGroup errgroup.Group

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	halfClosed := make(chan struct{}, 2)
	go func() {
		<-halfClosed
		<-halfClosed
		cancel()
	}()

	errGroup.Go(func() error {
		<-ctx.Done()
		left.Close()
		right.Close()
		return ctx.Err()
	})

	errGroup.Go(func() error {
		_, err := io.Copy(right, left)
		if hc, ok := right.(HalfCloser); ok {
			hc.CloseWrite()
		} else {
			right.Close()
		}
		halfClosed <- struct{}{}
		return err
	})

	errGroup.Go(func() error {
		_, err := io.Copy(left, right)
		if hc, ok := left.(HalfCloser); ok {
			hc.CloseWrite()
		} else {
			left.Close()
		}
		halfClosed <- struct{}{}
		return err
	})

	return errGroup.Wait()
}
