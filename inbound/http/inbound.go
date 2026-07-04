package http

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/aomori446/kage/core"
	"github.com/aomori446/kage/outbound/shadowsocks"
)

type Inbound struct {
	ListenAddr string
	ServerAddr string

	Method string
	Key    []byte

	ctx       context.Context
	proxy     *httputil.ReverseProxy
	proxyOnce sync.Once
}

func (p *Inbound) Run(ctx context.Context) error {
	p.ctx = ctx
	ln, err := net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	slog.Info("HTTP inbound listening", "addr", p.ListenAddr)

	srv := &http.Server{
		Addr:    p.ListenAddr,
		Handler: p,
	}

	return srv.Serve(ln)
}

func (p *Inbound) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	target := req.RequestURI
	method := req.Method
	if method == http.MethodConnect {
		target = "https://" + target
	}

	slog.Info("HTTP proxying", "method", method, "target", target, "client", req.RemoteAddr)

	if method == http.MethodConnect {
		p.handleCONNECT(w, req)
	} else {
		p.proxyOnce.Do(p.initProxy)
		p.proxy.ServeHTTP(w, req)
	}
}

func (p *Inbound) handleCONNECT(w http.ResponseWriter, req *http.Request) {
	targetAddr, err := core.ParseAddress(req.Host)
	if err != nil {
		slog.Error("Parse target address failed", "host", req.Host, "error", err)
		http.Error(w, "Proxy error: invalid target address", http.StatusBadRequest)
		return
	}

	shadowConn, err := shadowsocks.NewConn(p.ServerAddr, p.Method, p.Key, targetAddr, nil)
	if err != nil {
		slog.Error("Dial Shadowsocks failed", "error", err)
		http.Error(w, "Proxy error: connection failed", http.StatusBadGateway)
		return
	}
	defer shadowConn.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		slog.Error("Hijack failed: http.ResponseWriter is not a hijacker")
		http.Error(w, "Proxy error: hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		slog.Error("Hijack failed", "error", err)
		return
	}
	defer clientConn.Close()

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		slog.Error("Send 200 Established failed", "error", err)
		return
	}

	shadowConn.RelayWith(p.ctx, clientConn)
}

func (p *Inbound) initProxy() {
	p.proxy = &httputil.ReverseProxy{
		Director: func(outReq *http.Request) {
			outReq.URL.Scheme = "http"
			outReq.URL.Host = outReq.Host
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				targetAddr, err := core.ParseAddress(addr)
				if err != nil {
					return nil, err
				}
				shadowConn, err := shadowsocks.NewConn(p.ServerAddr, p.Method, p.Key, targetAddr, nil)
				if err != nil {
					return nil, err
				}
				return shadowConn, nil
			},
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			MaxIdleConnsPerHost: 20,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return
			}
			slog.Warn("http: proxy error", "error", err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}
