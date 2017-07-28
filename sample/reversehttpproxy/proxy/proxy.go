package main

import (
	"fmt"
	"net"
	"net/http"

	"log"

	"net/http/httputil"
	"net/url"

	"crypto/rand"

	"encoding/base64"

	"github.com/flynn/noise"
	"github.com/namsral/flag"
	"github.com/oxtoacart/bpool"
	"gopkg.in/noisesocket.v0"
)

var (
	serverPub []byte
	host      string
)

func init() {
	flag.StringVar(&host, "host", "noise.virgilsecurity.com", "host to connect to")
}

func main() {

	fmtstr := "https://%s:%d"
	go startProxy(fmt.Sprintf(fmtstr, host, 13242), ":1080")
	go startProxy(fmt.Sprintf(fmtstr, host, 13243), ":1081")
	startProxy(fmt.Sprintf(fmtstr, host, 13244), ":1082")

}

func startProxy(backendUrlString, listen string) {
	backendUrl, _ := url.Parse(backendUrlString)
	reverseProxy := httputil.NewSingleHostReverseProxy(backendUrl)

	transport := &proxyTransport{
		Transport: http.Transport{
		//DisableKeepAlives: true,
		},
	}

	transport.DialTLS = func(network, addr string) (net.Conn, error) {
		clientKeys := noise.DH25519.GenerateKeypair(rand.Reader)
		conn, err := noisesocket.Dial(addr, clientKeys, serverPub)
		transport.conn = conn
		return conn, err

	}

	reverseProxy.Transport = transport
	reverseProxy.BufferPool = bpool.NewBytePool(10, 32*10124)
	fmt.Println("Reverse proxy server is listening on ", listen, fmt.Sprintf(". Try http://localhost%s", listen))
	log.Fatal(http.ListenAndServe(listen, reverseProxy))
}

type proxyTransport struct {
	http.Transport
	conn *noisesocket.Conn
}

//add headers with info from proxy

func (p *proxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := p.Transport.RoundTrip(req)
	if err == nil {
		resp.Header.Add("X-HANDSHAKE-HASH", base64.StdEncoding.EncodeToString(p.conn.ChannelBinding()))
		resp.Header.Add("X-PEER-KEY", base64.StdEncoding.EncodeToString(serverPub))
	}

	return resp, err
}
