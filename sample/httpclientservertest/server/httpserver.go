package main

import (
	"net/http"

	"os"

	"crypto/rand"

	"fmt"

	"flag"

	"encoding/base64"

	"time"

	"io"
	"io/ioutil"

	"github.com/flynn/noise"
	"github.com/go-noisesocket/noisesocket"
)

var (
	listen = flag.String("listen", ":5000", "Port to listen on")
)

func main() {

	// go startHttpServer()
	startNoiseSocketServer()

}

func startNoiseSocketServer() {
	server := &http.Server{
		Addr:         *listen,
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	}
	// server.SetKeepAlivesEnabled(true)

	buf := make([]byte, 1) // send 4113 bytes
	rand.Read(buf)
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(ioutil.Discard, r.Body)
		w.Write(buf)
	})

	pub, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")
	priv, _ := base64.StdEncoding.DecodeString("vFilCT/FcyeShgbpTUrpru9n5yzZey8yfhsAx6DeL80=")

	serverKeys := noise.DHKey{
		Public:  pub,
		Private: priv,
	}

	l, err := noisesocket.Listen(":12888", &noisesocket.ConnectionConfig{StaticKey: serverKeys})
	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}

	fmt.Println("Starting server...")
	if err := server.Serve(l); err != nil {
		panic(err)
	}
}
