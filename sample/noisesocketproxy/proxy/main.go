package main

import (
	c "crypto/rand"
	"io"
	"log"
	"net"
	"os"

	"github.com/flynn/noise"

	"github.com/go-noisesocket/noisesocket"
)

func makeBuffer() []byte {
	return make([]byte, noisesocket.MaxPayloadSize)
}

var pool = make([][]byte, 20)

var buffer = make(chan []byte, 50)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: proxy local remote")
	}
	localAddr := os.Args[1]
	remoteAddr := os.Args[2]

	serverKeys, err := noise.DH25519.GenerateKeypair(c.Reader)

	listener, err := noisesocket.Listen(localAddr, &noisesocket.ConnectionConfig{StaticKey: serverKeys})
	if listener == nil {
		log.Fatalf("cannot listen: %v", err)
	}
	for {
		conn, err := listener.Accept()
		if conn == nil {
			log.Printf("accept failed: %v", err)
		}
		go forward(conn, remoteAddr)
	}
}

func forward(local net.Conn, remoteAddr string) {
	remote, err := net.Dial("tcp", remoteAddr)
	if remote == nil {
		log.Printf("dial failed: %v\n", err)
		return
	}

	go func() {
		var b []byte
		select {
		case b = <-buffer:
			break
		default:
			b = makeBuffer()
		}
		io.CopyBuffer(local, remote, b)
		remote.Close()
		local.Close()

		select {
		case buffer <- b:
		default:
		}

	}()

	go func() {
		var b []byte
		select {
		case b = <-buffer:
			break
		default:
			b = makeBuffer()
		}
		io.CopyBuffer(remote, local, b)
		remote.Close()
		local.Close()

		select {
		case buffer <- b:
		default:
		}

	}()

}
