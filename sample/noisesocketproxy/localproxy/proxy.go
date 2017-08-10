package main

import (
	"fmt"
	"net/http"

	"crypto/rand"

	"io/ioutil"
	"time"

	"log"
	"os"

	"bytes"
	"net"

	"crypto/tls"

	"github.com/flynn/noise"
	"gopkg.in/noisesocket.v0"
)

var (
	host string
)

func main() {

	if len(os.Args) != 3 {
		log.Fatal("usage: localproxy noiseAddress TLSAddress")
	}

	fmt.Printf("starting proxy to %s\n", os.Args[1])
	go startTLSProxy(os.Args[2], ":1081")
	startProxy(os.Args[1], ":1080")

}

func startTLSProxy(noiseAddress, listen string) {
	server := &http.Server{
		Addr:         listen,
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	}

	clientKeys := noise.DH25519.GenerateKeypair(rand.Reader)

	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		buf, err := TLSRoundTrip(noiseAddress, clientKeys, body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		w.Header().Set("Server", "A Go Web Server")
		w.WriteHeader(200)
		w.Write(buf)
	})

	fmt.Println("started local http->tls proxy on port 1081")
	fmt.Println(server.ListenAndServe())
}

func TLSRoundTrip(noiseAddress string, clientKeys noise.DHKey, body []byte) ([]byte, error) {

	transport := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //noisesocket.Dial(addr, clientKeys, nil)
		},
	}

	cli := &http.Client{Transport: transport}

	req, err := http.NewRequest("POST", "https://"+noiseAddress+"/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}

func startProxy(noiseAddress, listen string) {
	server := &http.Server{
		Addr:         listen,
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	}

	clientKeys := noise.DH25519.GenerateKeypair(rand.Reader)

	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		buf, err := noiseRoundTrip(noiseAddress, clientKeys, body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		w.Header().Set("Server", "A Go Web Server")
		w.WriteHeader(200)
		w.Write(buf)
	})

	fmt.Println("started local http->noise proxy on port 1080")
	fmt.Println(server.ListenAndServe())
}

func noiseRoundTrip(noiseAddress string, clientKeys noise.DHKey, body []byte) ([]byte, error) {

	transport := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			//fmt.Println("dial!")
			return noisesocket.Dial(addr, &noisesocket.ConnectionConfig{StaticKey: clientKeys})
		},
	}

	cli := &http.Client{Transport: transport}

	req, err := http.NewRequest("POST", "https://"+noiseAddress+"/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}
