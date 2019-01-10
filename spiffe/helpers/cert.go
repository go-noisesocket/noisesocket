package helpers

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

func GetCertPool(path string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	certPEM, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file '%s': %s", path, err)
	}

	ok := pool.AppendCertsFromPEM(certPEM)
	if !ok {
		return nil, fmt.Errorf("failed to append a certificate: %s", err)
	}
	return pool, nil
}
