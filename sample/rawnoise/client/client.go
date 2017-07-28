package client

import (
	"encoding/base64"

	"fmt"
	"time"

	"github.com/flynn/noise"
	"gopkg.in/noisesocket.v0"
)

func main() {

	pub1, _ := base64.StdEncoding.DecodeString("L9Xm5qy17ZZ6rBMd1Dsn5iZOyS7vUVhYK+zby1nJPEE=")
	priv1, _ := base64.StdEncoding.DecodeString("TPmwb3vTEgrA3oq6PoGEzH5hT91IDXGC9qEMc8ksRiw=")

	//serverPub, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")

	clientKeys := noise.DHKey{
		Public:  pub1,
		Private: priv1,
	}

	conn, err := noisesocket.Dial("127.0.0.1:10000", clientKeys, nil)
	if err != nil {
		panic(err)
	}
	threads := 1
	count := 5 * 1000
	c := make(chan bool, threads)
	t := time.Now()
	for i := 0; i < threads; i++ {
		go func(t int) {
			buf := make([]byte, 4096)

			for j := 0; j < count; j++ {

				_, err = conn.Write(buf)
				if err != nil {
					panic(err)
				}

				_, err = conn.Read(buf)
				if err != nil {
					panic(err)
				}
			}
			c <- true

		}(i)
	}

	for j := 0; j < threads; j++ {
		<-c
	}
	fmt.Println(time.Since(t).Seconds())

}
