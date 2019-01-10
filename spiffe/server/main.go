package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/spiffe/go-spiffe/uri"
	"io/ioutil"
	"net/http"
	"noisesocket/spiffe/helpers"
	"os"
	"time"

	"github.com/flynn/noise"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/noisesocket.v0"
	"log"
)

var (
	clientCA, clientRoot *x509.CertPool
	serverCertPEM        []byte
)

var (
	allowedURIs = kingpin.Flag("allow-uri", "Allow clients with given SPIFFE URI ID.").PlaceHolder("URI").Strings()
)

func init() {
	var err error

	clientCA, err = helpers.GetCertPool("./keys/test3-IntermediateCA.pem")
	if err != nil {
		panic(err)
	}
	clientRoot, err = helpers.GetCertPool("./keys/test3-RootCA.pem")
	if err != nil {
		panic(err)
	}
	serverCertPEM, err = ioutil.ReadFile("./keys/server-cert.pem")
	if err != nil {
		panic(err)
	}
}

func main() {
	kingpin.Parse()
	err := startServer()
	if err != nil {
		panic("failed to start server: " + err.Error())
	}
}

func startServer() error {
	fmt.Println("Starting server...")

	pub, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")
	priv, _ := base64.StdEncoding.DecodeString("vFilCT/FcyeShgbpTUrpru9n5yzZey8yfhsAx6DeL80=")

	serverKeys := noise.DHKey{
		Public:  pub,
		Private: priv,
	}

	signature, err := helpers.Sign(pub, "./keys/server-key.pem")
	if err != nil {
		return err
	}

	info := &helpers.AuthInfo{Certificate: serverCertPEM, Signature: signature}
	payload, err := json.Marshal(info)
	if err != nil {
		return err
	}

	l, err := noisesocket.Listen(":12888", &noisesocket.ConnectionConfig{
		StaticKey:      serverKeys,
		VerifyCallback: verifyCallback,
		Payload:        payload,
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

	verifyOpts := x509.VerifyOptions{
		Roots:         clientRoot,
		Intermediates: clientCA,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	cert, signature, err := helpers.GetCertificateAndSignature(data)
	if err != nil {
		return fmt.Errorf("unable to get client certificate: %s", err)
	}

	_, err = cert.Verify(verifyOpts)
	if err != nil {
		return fmt.Errorf("unable to veirfy client certificate: %s", err)
	}

	err = helpers.ValidateURI(cert, *allowedURIs)
	if err != nil {
		return fmt.Errorf("client URI is not allowed: %s", err)
	}

	err = helpers.ValidateSignature(publicKey, cert, signature)
	if err != nil {
		return fmt.Errorf("unable to verify noise client public key: %s", err)
	}

	id, err := uri.GetURINamesFromCertificate(cert)
	if err == nil {
		log.Printf("Access from %s permitted", id[0])
	}

	return nil
}

func Handler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
