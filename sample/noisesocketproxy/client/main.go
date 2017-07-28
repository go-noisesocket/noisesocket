package main

import (
	"crypto/rand"

	"log"

	"time"

	"fmt"

	"os"

	"net"
	"net/http"

	"bytes"

	"crypto/tls"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: client address")
	}
	//clientKeys := noise.DH25519.GenerateKeypair(rand.Reader)

	buf := make([]byte, 420)

	rand.Read(buf)

	t := time.Now()
	i := 0
	for time.Now().Sub(t) < (time.Second * 30) {

		transport := &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				//fmt.Println("dial!")
				return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //noisesocket.Dial(addr, clientKeys, nil)
			},
		}

		cli := &http.Client{Transport: transport}

		req, err := http.NewRequest("POST", "https://localhost:12807/", bytes.NewReader(buf))
		if err != nil {
			panic(err)
		}
		_, err = cli.Do(req)
		if err != nil {
			panic(err)
		}
		i++
	}

	fmt.Println(float32(i) / 30.0)
}

func xxx() {

}
