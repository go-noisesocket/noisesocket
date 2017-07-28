package noisesocket

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/dchest/siphash"
)

var (
	k0, k1 = generateHashKey()
)

func generateHashKey() (uint64, uint64) {

	key := make([]byte, 16)
	_, err := rand.Read(key)

	if err != nil {
		panic(err)
	}

	return binary.BigEndian.Uint64(key), binary.BigEndian.Uint64(key[8:])
}

func HashKey(data []byte) uint64 {
	return siphash.Hash(k0, k1, data)
}
