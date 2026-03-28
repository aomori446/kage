package inbound

import (
	"context"
	"errors"
	"kage/pkg/core"
	"kage/pkg/crypto/shadowsocks"
	"kage/pkg/proxy/outbound"
	"kage/pkg/transport/tcp"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"
)

type HttpProxy struct {
	ListenAddr string
	ServerAddr string
	Method     string
	
	Key []byte
	
	proxy     *httputil.ReverseProxy
	proxyOnce sync.Once
}

func (p *HttpProxy) Listen(ctx context.Context) error {
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

func (p *HttpProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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

func (p *HttpProxy) handleCONNECT(w http.ResponseWriter, req *http.Request) {
	targetAddr, err := core.ParseAddress(req.Host)
	if err != nil {
		slog.Error("Parse target address failed", "host", req.Host, "error", err)
		http.Error(w, "Proxy error: invalid target address", http.StatusBadRequest)
		return
	}
	
	shadowConn, err := p.dialShadowsocks(targetAddr, nil)
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
	
	tcp.Relay(context.Background(), clientConn, shadowConn)
}

func (p *HttpProxy) initProxy() {
	p.proxy = &httputil.ReverseProxy{
		Director: func(outReq *http.Request) {
			outReq.URL.Scheme = "http"
			outReq.URL.Host = outReq.Host
			outReq.RequestURI = ""
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				targetAddr, err := core.ParseAddress(addr)
				if err != nil {
					return nil, err
				}
				shadowConn, err := p.dialShadowsocks(targetAddr, nil)
				if err != nil {
					return nil, err
				}
				if _, err = shadowConn.Write(nil); err != nil {
					shadowConn.Close()
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

func (p *HttpProxy) dialShadowsocks(targetAddr *core.Address, initialPayload []byte) (*outbound.Shadowsocks, error) {
	serverConn, err := net.DialTimeout("tcp", p.ServerAddr, time.Second*3)
	if err != nil {
		return nil, err
	}
	
	cipher, err := shadowsocks.NewCipher(p.Method, p.Key)
	if err != nil {
		serverConn.Close()
		return nil, err
	}
	
	return outbound.NewShadowsocks(serverConn, p.Method, cipher, targetAddr, initialPayload), nil
}
