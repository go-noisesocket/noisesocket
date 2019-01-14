package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/flynn/noise"
	"gopkg.in/noisesocket.v0"
	h "gopkg.in/noisesocket.v0/spiffe/helpers"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
)

var (
	serverCA, serverRoot *x509.CertPool
	clientCertPEM        []byte
)

func init() {
	var err error
	serverCA, err = h.GetCertPool("./keys/test1-IntermediateCA.pem")
	if err != nil {
		log.Fatal(err)
	}
	serverRoot, err = h.GetCertPool("./keys/test1-RootCA.pem")
	if err != nil {
		panic(err)
	}
	clientCertPEM, err = ioutil.ReadFile("./keys/client-cert.pem")
	if err != nil {
		panic(err)
	}
}

func main() {
	cli, err := StartClient()

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

func StartClient() (*http.Client, error) {
	pub1, _ := base64.StdEncoding.DecodeString("L9Xm5qy17ZZ6rBMd1Dsn5iZOyS7vUVhYK+zby1nJPEE=")
	priv1, _ := base64.StdEncoding.DecodeString("TPmwb3vTEgrA3oq6PoGEzH5hT91IDXGC9qEMc8ksRiw=")

	clientKeys := noise.DHKey{
		Public:  pub1,
		Private: priv1,
	}

	signature, err := h.Sign(pub1, "./keys/client-key.pem")

	if err != nil {
		return nil, err
	}
	info := &h.AuthInfo{Certificate: clientCertPEM, Signature: signature}

	payload, err := json.Marshal(info)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{

		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := noisesocket.Dial(addr, &noisesocket.ConnectionConfig{
				StaticKey:      clientKeys,
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
	if len(publicKey) == 0 {
		return nil
	}

	verifyOpts := x509.VerifyOptions{
		Roots:         serverRoot,
		Intermediates: serverCA,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
		},
	}

	cert, signature, err := h.GetCertificateAndSignature(data)
	if err != nil {
		return fmt.Errorf("unable to get server certificate: %s", err)
	}

	_, err = cert.Verify(verifyOpts)
	if err != nil {
		return fmt.Errorf("unable to verify server certificate: %s", err)
	}

	err = h.ValidateSignature(publicKey, cert, signature)
	if err != nil {
		return fmt.Errorf("unable to verify noise server public key: %s", err)
	}
	return nil

}
