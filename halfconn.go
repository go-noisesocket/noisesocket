package noisesocket

import (
	"encoding/binary"
	"sync"

	"math"

	"fmt"

	"github.com/flynn/noise"
	"github.com/pkg/errors"
)

// halfConn represents inbound or outbound connection state with its own cipher
type halfConn struct {
	sync.Mutex
	cs      *noise.CipherState
	err     error
	bfree   *buffer // list of free blocks
	padding uint16
}

const (
	uint16Size = 2  // uint16 takes 2 bytes
	macSize    = 16 // GCM and Poly1305 add 16 byte MACs
)

func (h *halfConn) encryptIfNeeded(block *buffer) []byte {

	if h.cs != nil {

		payloadSize := len(block.data) - uint16Size + macSize
		if payloadSize > math.MaxUint16 {
			panic("data is too big to be sent")
		}

		block.data, _ = h.cs.Encrypt(block.data[:uint16Size], nil, block.data[uint16Size:])
		binary.BigEndian.PutUint16(block.data, uint16(payloadSize))

		return block.data
	}

	if len(block.data) > MaxPayloadSize-uint16Size {
		panic("data is too big to be sent")
	}

	binary.BigEndian.PutUint16(block.data, uint16(len(block.data)-uint16Size))

	return block.data
}

// decryptIfNeeded checks and strips the mac and decrypts the data in b.
// Returns error if parsing failed

func (h *halfConn) decryptIfNeeded(b *buffer) (off, length int, err error) {

	// pull out payload

	payload := b.data[uint16Size:]

	packetLen := binary.BigEndian.Uint16(b.data)
	if int(packetLen) != len(payload) { // this is supposed to be checked before method call
		panic("invalid payload size")
	}

	if h.cs != nil {
		payload, err = h.cs.Decrypt(payload[:0], nil, payload)
		if err != nil {
			return 0, 0, err
		}
		if len(payload) < uint16Size {
			return 0, 0, errors.New("too small packet data")
		}

		dataLen := binary.BigEndian.Uint16(payload)
		// fmt.Println("decrypt len", dataLen)

		if dataLen > (uint16(len(payload))) {
			return 0, 0, errors.New(fmt.Sprintf("invalid packet data: %d %d", dataLen, len(payload)))
		}
		b.resize(uint16Size + uint16Size + int(dataLen))
		return uint16Size + uint16Size, int(dataLen), nil
	}

	return uint16Size, len(payload), nil
}

func (h *halfConn) setErrorLocked(err error) error {
	h.err = err
	return err
}

// newBlock allocates a new packet, from hc's free list if possible.
func (h *halfConn) newBlock() *buffer {
	b := h.bfree
	if b == nil {
		return new(buffer)

	}
	h.bfree = b.link
	b.link = nil
	b.resize(0)
	return b
}

// freeBlock returns a packet to hc's free list.
// The protocol is such that each side only has a packet or two on
// its free list at a time, so there's no need to worry about
// trimming the list, etc.
func (h *halfConn) freeBlock(b *buffer) {
	b.link = h.bfree
	h.bfree = b

}

// splitBlock splits a packet after the first n bytes,
// returning a packet with those n bytes and a
// packet with the remainder.  the latter may be nil.
func (h *halfConn) splitBlock(b *buffer, n int) (*buffer, *buffer) {
	if len(b.data) <= n {
		return b, nil
	}
	bb := h.newBlock()
	bb.resize(len(b.data) - n)
	copy(bb.data, b.data[n:])
	b.data = b.data[0:n]
	return b, bb
}
