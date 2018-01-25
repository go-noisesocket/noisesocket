package noisesocket

import (
	"encoding/binary"

	"crypto/rand"

	"bytes"
	"io"

	"fmt"

	"github.com/flynn/noise"
	"github.com/pkg/errors"
)

var negotiationData []byte
var initString = []byte("NoiseSocketInit1")

func init() {
	negotiationData = make([]byte, 6)
	binary.BigEndian.PutUint16(negotiationData, 1) //version
	negotiationData[2] = NOISE_DH_CURVE25519
	negotiationData[3] = NOISE_CIPHER_AESGCM
	negotiationData[4] = NOISE_HASH_BLAKE2b
	//negotiationData[5] //pattern. determined at runtime
}

// ComposeInitiatorHandshakeMessage generates handshakeState and the first noise message.
func ComposeInitiatorHandshakeMessage(s noise.DHKey, rs []byte, payload []byte, ePrivate []byte) (negData, msg []byte, state *noise.HandshakeState, err error) {

	if len(rs) != 0 && len(rs) != noise.DH25519.DHLen() {
		return nil, nil, nil, errors.New("only 32 byte curve25519 public keys are supported")
	}

	var pattern noise.HandshakePattern

	negData = make([]byte, 6)
	copy(negData, negotiationData)

	if len(rs) == 0 {
		pattern = noise.HandshakeXX
		negData[5] = NOISE_PATTERN_XX
	} else {
		pattern = noise.HandshakeIK
		negData[5] = NOISE_PATTERN_IK
	}

	var random io.Reader
	if len(ePrivate) == 0 {
		random = rand.Reader
	} else {
		random = bytes.NewBuffer(ePrivate)
	}

	prologue := make([]byte, 2, uint16Size+len(negData))
	binary.BigEndian.PutUint16(prologue, uint16(len(negData)))
	prologue = append(prologue, negData...)
	prologue = append(initString, prologue...)
	state, err = noise.NewHandshakeState(noise.Config{
		StaticKeypair: s,
		Initiator:     true,
		Pattern:       pattern,
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashBLAKE2b),
		PeerStatic:    rs,
		Prologue:      prologue,
		Random:        random,
	})

	if err != nil{
		return
	}

	msg, _, _, err = state.WriteMessage(msg, payload)

	return
}

func ParseNegotiationData(data []byte, s noise.DHKey) (state *noise.HandshakeState, err error) {

	if len(data) != 6 {
		return nil, errors.New("Invalid negotiation data length")
	}

	version := binary.BigEndian.Uint16(data)
	if version != 1 {
		return nil, errors.New("unsupported version")
	}

	if data[2] != NOISE_DH_CURVE25519 {
		fmt.Println(data[3])
		return nil, errors.New("unsupported DH")
	}
	var ok bool
	var cipher noise.CipherFunc
	var hash noise.HashFunc
	var pattern noise.HandshakePattern

	cipherIndex := data[3]
	if cipher, ok = ciphers[cipherIndex]; !ok {
		return nil, errors.New("unsupported cipher")
	}

	hashIndex := data[4]
	if hash, ok = hashes[hashIndex]; !ok {
		return nil, errors.New("unsupported hash")
	}

	patternIndex := data[5]

	if pattern, ok = patterns[patternIndex]; !ok {
		return nil, errors.New("unsupported pattern")
	}

	prologue := make([]byte, 2, uint16Size+len(data))
	binary.BigEndian.PutUint16(prologue, uint16(len(data)))
	prologue = append(prologue, data...)
	prologue = append(initString, prologue...)
	state, err = noise.NewHandshakeState(noise.Config{
		StaticKeypair: s,
		Pattern:       pattern,
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, cipher, hash),
		Prologue:      prologue,
	})
	return
}
