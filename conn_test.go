package noisesocket

import (
	"fmt"
	"net"
	"testing"
)

func TestConnection(t *testing.T) {

	/*pub, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")
	priv, _ := base64.StdEncoding.DecodeString("vFilCT/FcyeShgbpTUrpru9n5yzZey8yfhsAx6DeL80=")

	serverKeys := noise.DHKey{
		Public:  pub,
		Private: priv,
	}

	l, err := Listen("127.0.0.1:0", serverKeys)
	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}
	fmt.Println(l.Addr().String())
	for {
		con, err := l.Accept()
		if err != nil {
			panic(err)
		}
		go serve(con)
	}*/
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
