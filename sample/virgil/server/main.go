package main

import (
	"errors"
	"flag"
	"fmt"
	virgil2 "gopkg.in/noisesocket.v0/sample/virgil"
	"net/http"
	"os"
	"time"

	"crypto/rand"
	"encoding/json"

	"github.com/flynn/noise"
	"gopkg.in/noisesocket.v0"
	"gopkg.in/virgil.v4/virgilapi"
)

var mail, clientMail string

func init() {
	flag.StringVar(&mail, "email", "", "your email")
	flag.StringVar(&clientMail, "clientMail", "", "client email")
}

func main() {
	flag.Parse()

	key, err := virgil2.InitVirgilCard(mail)

	if err != nil {
		panic(err)
	}

	startServer(mail, key)
}
func startServer(identity string, key *virgilapi.Key) {

	keys, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}
	signature, err := key.Sign(keys.Public)
	if err != nil {
		panic(err)
	}

	info := &virgil2.AuthInfo{Identity: identity, Signature: signature}

	payload, err := json.Marshal(info)

	if err != nil {
		panic(err)
	}

	l, err := noisesocket.Listen(":12888", &noisesocket.ConnectionConfig{
		StaticKey:      keys,
		Payload:        payload,
		VerifyCallback: verifyCallback,
	})

	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:         ":12888",
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	}

	server.Handler = http.HandlerFunc(Handler)

	panic(server.Serve(l))

}

func verifyCallback(publicKey []byte, data []byte) error {
	if len(publicKey) == 0 {
		return nil
	}
	identity, signature, err := virgil2.GetIdentityAndSignature(data)

	if err != nil {
		return err
	}

	if identity != clientMail {
		return errors.New("invalid identity")
	}

	return virgil2.ValidateSignature(publicKey, signature, identity)
}

func Handler(w http.ResponseWriter, r *http.Request) {

	w.WriteHeader(http.StatusOK)
}
