package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/flynn/noise"

	"github.com/pkg/errors"
	"gopkg.in/noisesocket.v0"
	v "gopkg.in/noisesocket.v0/virgil"
	"gopkg.in/virgil.v4/virgilapi"
)

var mail, serverMail string

func init() {
	flag.StringVar(&mail, "email", "", "your email")
	flag.StringVar(&serverMail, "serverMail", "", "client email")
}

func main() {

	flag.Parse()

	key, err := v.InitVirgilCard(mail)

	if err != nil {
		panic(err)
	}

	cli, err := StartClient(mail, key)

	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest("GET", "https://127.0.0.1:12888/", nil)
	if err != nil {
		panic(err)
	}

	resp, err := cli.Do(req)
	if err != nil {
		panic(err)
	}

	fmt.Println(resp.StatusCode)

	_, err = io.Copy(ioutil.Discard, resp.Body)
	if err != nil {
		panic(err)
	}
	err = resp.Body.Close()
	if err != nil {
		panic(err)
	}
}

func StartClient(identity string, key *virgilapi.Key) (*http.Client, error) {

	keys := noise.DH25519.GenerateKeypair(rand.Reader)

	signature, err := key.Sign(keys.Public)
	if err != nil {
		return nil, err
	}

	info := &v.AuthInfo{Identity: identity, Signature: signature}

	payload, err := json.Marshal(info)

	if err != nil {
		return nil, err
	}

	transport := &http.Transport{

		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := noisesocket.Dial(addr, &noisesocket.ConnectionConfig{
				StaticKey:      keys,
				Payload:        payload,
				VerifyCallback: VerifyCallback,
			})
			if err != nil {
				fmt.Println("Dial", err)
			}

			return conn, err
		},
	}
	cli := &http.Client{
		Transport: transport,
	}

	return cli, nil
}

func VerifyCallback(publicKey []byte, data []byte) error {

	identity, signature, err := v.GetIdentityAndSignature(data)

	if err != nil {
		return err
	}

	if identity != serverMail {
		return errors.New("invalid identity")
	}

	return v.ValidateSignature(publicKey, signature, identity)
}
