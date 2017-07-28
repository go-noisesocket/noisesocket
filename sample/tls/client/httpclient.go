package client

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sort"
	"sync"
	"time"
)

func main() {

	t := time.Now()
	n := 1000
	buf := make([]byte, 55)
	rand.Read(buf)
	c := make(chan bool, 10)

	threads := 20

	transport := &http.Transport{
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 1,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	stats := make(map[int]int)
	mu := sync.Mutex{}
	go func(stats map[int]int) {

		for {
			time.Sleep(time.Second * 1)
			mu.Lock()
			var keys []int
			for k := range stats {
				keys = append(keys, k)
			}
			sort.Ints(keys)

			for _, k := range keys {
				fmt.Printf("%d:%d ", k, stats[k])
			}
			fmt.Println()
			mu.Unlock()

		}
	}(stats)

	for j := 0; j < threads; j++ {
		go func(t int) {

			cli := &http.Client{
				Transport: transport,
			}
			for i := 0; i < n; i++ {
				reader := bytes.NewReader(buf)
				req, err := http.NewRequest("POST", "https://127.0.0.1:5000/", reader)
				if err != nil {
					panic(err)
				}

				resp, err := cli.Do(req)
				if err != nil {
					panic(err)
				}
				_, err = io.Copy(ioutil.Discard, resp.Body)

				if err != nil {
					panic(err)
				}
				err = resp.Body.Close()
				if err != nil {
					panic(err)
				}
				mu.Lock()
				stats[t] = i
				mu.Unlock()
			}
			fmt.Println("donedone", t)
			c <- true
		}(j)
	}

	for j := 0; j < threads; j++ {
		<-c
	}
	fmt.Println(time.Since(t).Seconds())
}
