package server

import (
	"encoding/base64"
	"fmt"
	"os"

	"net"

	"github.com/flynn/noise"
	"gopkg.in/noisesocket.v0"
)

func main() {

	pub, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")
	priv, _ := base64.StdEncoding.DecodeString("vFilCT/FcyeShgbpTUrpru9n5yzZey8yfhsAx6DeL80=")

	serverKeys := noise.DHKey{
		Public:  pub,
		Private: priv,
	}
	l, err := noisesocket.Listen(":10000", serverKeys)
	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}
	for {
		con, err := l.Accept()
		if err != nil {
			panic(err)
		}
		go serve(con)
	}
}
func serve(conn net.Conn) {
	buf := make([]byte, 4096)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			fmt.Println(err)
			return
		}
		_, err = conn.Write(buf)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}
