package httpproxy

import (
	"bytes"
	"kage/pkg/core"
	"net"
	"net/http"
)

func HandleRequest(req *http.Request) (targetAddr *core.Address, initialPayload []byte, err error) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if _, _, err = net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "80")
	}
	
	targetAddr, err = core.ParseAddress(host)
	if err != nil {
		return nil, nil, err
	}
	
	req.RequestURI = req.URL.RequestURI()
	
	var hopHeaders = []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailers",
		"Transfer-Encoding", "Upgrade",
	}
	
	for _, h := range hopHeaders {
		req.Header.Del(h)
	}
	
	var buf bytes.Buffer
	if err = req.Write(&buf); err != nil {
		return nil, nil, err
	}
	
	return targetAddr, buf.Bytes(), nil
}
