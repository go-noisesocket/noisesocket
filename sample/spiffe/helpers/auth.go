package helpers

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
)

type AuthInfo struct {
	Certificate []byte `json:"certificate"`
	Signature   []byte `json:"signature"`
}

func VerifyURI(uris []*url.URL, allowedURIs []string) error {
	for _, expectedURI := range allowedURIs {
		for _, u := range uris {
			if u.String() == expectedURI {
				return nil
			}
		}
	}
	return errors.New("invalid principal, or principal not allowed")
}

func Sign(data []byte, keyPath string) ([]byte, error) {
	priv, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(priv))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse RSA private key")
	}

	rng := rand.Reader
	hashed := sha256.Sum256(data)

	signature, err := rsa.SignPKCS1v15(rng, rsaPrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("fail to sign data: %s ", err)
	}

	return signature, nil
}

func ValidateSignature(data []byte, cert *x509.Certificate, signature []byte) error {
	rsaPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("failed to get RSA public key from certificate")
	}

	hashed := sha256.Sum256(data)
	err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return fmt.Errorf("invalid signature: %s", err)
	}
	return nil
}

func ValidateURI(cert *x509.Certificate, allowedURIs []string) error {
	err := VerifyURI(cert.URIs, allowedURIs)
	if err != nil {
		return fmt.Errorf("client URI is not allowed: %s", err)
	}
	return nil
}

func GetCertificateAndSignature(data []byte) (*x509.Certificate, []byte, error) {
	var info *AuthInfo
	// unpad padded data before handling
	err := json.Unmarshal(data[2:], &info)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse payload: %s", err)
	}

	block, _ := pem.Decode(info.Certificate)
	if block == nil {
		return nil, nil, errors.New("failed to load certificate from payload")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %s ", err)
	}

	return cert, info.Signature, nil
}
