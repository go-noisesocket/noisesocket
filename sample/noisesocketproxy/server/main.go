package main

import (
	"crypto/rand"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"crypto/tls"
	"fmt"

	"github.com/flynn/noise"
	"gopkg.in/noisesocket.v0"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: server address tlsAddress")
	}

	go startTlsServer(os.Args[2])

	keys := noise.DH25519.GenerateKeypair(rand.Reader)

	l, err := noisesocket.Listen(os.Args[1], keys)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	server := &http.Server{
		Addr:         os.Args[1],
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	}
	server.SetKeepAlivesEnabled(false)

	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, r.Body)
	})
	fmt.Println("Starting noise http server...")
	if err := server.Serve(l); err != nil {
		panic(err)
	}
}

func startTlsServer(addr string) {
	server := &http.Server{
		Addr:         addr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	server.SetKeepAlivesEnabled(false)

	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, r.Body)
	})

	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Println(err)
		return
	}

	l, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
	})

	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}
	// Close the listener when the application closes.
	defer l.Close()

	fmt.Println("Starting TLS http server...")
	if err := server.Serve(l); err != nil {
		panic(err)
	}
}
