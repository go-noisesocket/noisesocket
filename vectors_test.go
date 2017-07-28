package noisesocket

import (
	"encoding/hex"
	"testing"

	"encoding/binary"

	"github.com/stretchr/testify/assert"
)

func TestVectors(t *testing.T) {

	/*vecfile, err := ioutil.ReadFile("testvectors.json")
	assert.NoError(t, err)

	var vector *Vector
	err = json.Unmarshal(vecfile, &vector)
	assert.NoError(t, err)

	ki := noise.DH25519.GenerateKeypair(bytes.NewBuffer(mustHex(vector.InitStatic)))
	kr := noise.DH25519.GenerateKeypair(bytes.NewBuffer(mustHex(vector.RespStatic)))
	re := mustHex(vector.RespEphemeral)

	initialMessage := Unpacket(t, mustHex(vector.InitialMessage))
	for i, session := range vector.Sessions {

		parsedPayload, rstate, cfg, msgIndex, err := ParseHandshake(kr, initialMessage, i, re)
		assert.NoError(t, err)
		assert.Equal(t, msgIndex, byte(i))

		peerstatic := mustHex(vector.InitRemoteStatic)
		if !cfg.UseRemoteStatic {
			peerstatic = nil
		}
		istate := noise.NewHandshakeState(noise.Config{
			StaticKeypair: ki,
			Initiator:     true,
			Pattern:       cfg.Pattern,
			CipherSuite:   noise.NewCipherSuite(cfg.DH, cfg.Cipher, cfg.Hash),
			PeerStatic:    peerstatic,
			Prologue:      mustHex(vector.Prologue),
			Random:        bytes.NewBuffer(mustHex(vector.InitEphemeral)),
		})
		istate.WriteMessage(nil, mustHex(session.Messages[0].Payload))

		ValidateMessage(t, session.Messages[0], parsedPayload)

		//compose answer
		pkt := InitializePacket() // 2 bytes for length

		if len(rstate.PeerStatic()) > 0 { //if we answer to IK, add one extra byte used for Noise pipes
			pkt.resize(len(pkt.data) + 2)
			pkt.data[len(pkt.data)-2] = msgIndex
		} else {
			pkt.resize(len(pkt.data) + 1)
			pkt.data[len(pkt.data)-1] = msgIndex
		}

		//var cs1i, cs2i, cs1r, cs2r *noise.CipherState
		var hsm []byte
		payload := new(buffer)
		for _, f := range session.Messages[1].Fields {
			payload.AddField(mustHex(f.Data), f.Type)
		}

		assert.Equal(t, payload.data, mustHex(session.Messages[1].Payload))

		var cs1i, cs2i, cs1r, cs2r *noise.CipherState
		//server responds
		hsm, cs1r, cs2r = rstate.WriteMessage(nil, payload.data)
		pkt.data = append(pkt.data, hsm...)
		binary.BigEndian.PutUint16(pkt.data, uint16(len(pkt.data)-2))

		assert.Equal(t, pkt.data, mustHex(session.Messages[1].Packet))

		sender := rstate
		receiver := istate

		// extract "pure" noise message on the initiator side, stripping IK byte if necessary
		rawPacket := Unpacket(t, pkt.data)
		if len(rstate.PeerStatic()) > 0 {
			assert.Equal(t, rawPacket[1], byte(0))
			hsm = rawPacket[2:]
		} else {
			hsm = rawPacket[1:]
		}

		//loop until handshake is done
		messageIndex := 1
		for {

			parsedPayload, cs1i, cs2i, err = receiver.ReadMessage(nil, hsm)
			assert.NoError(t, err)
			ValidateMessage(t, session.Messages[messageIndex], parsedPayload)
			messageIndex++

			if cs1r != nil && cs2r != nil && cs1i != nil && cs2i != nil {
				hh := mustHex(session.HandshakeHash)
				assert.Equal(t, receiver.ChannelBinding(), hh)
				assert.Equal(t, sender.ChannelBinding(), hh)

				for mi := messageIndex; mi < len(session.Messages); mi++ {
					pkti := InitializePacket()
					for _, f := range session.Messages[mi].Fields {
						pkti.AddField(mustHex(f.Data), f.Type)
					}
					assert.Equal(t, pkti.data[2:], mustHex(session.Messages[mi].Payload))

					pkti.data = cs1i.Encrypt(pkti.data[:2], nil, pkti.data[2:])
					binary.BigEndian.PutUint16(pkti.data, uint16(len(pkti.data)-2))

					assert.Equal(t, pkti.data, mustHex(session.Messages[mi].Packet))

					rawPacket := Unpacket(t, pkti.data)

					data, err := cs1r.Decrypt(pkti.data[:0], nil, rawPacket)
					assert.NoError(t, err)
					ValidateMessage(t, session.Messages[mi], data)

					cs1r, cs1i, cs2r, cs2i = cs2r, cs2i, cs1r, cs1i
				}

				break
			} else {
				sender, receiver = receiver, sender

				pkt = InitializePacket() // 2 bytes for length

				payload = new(buffer)
				for _, f := range session.Messages[messageIndex].Fields {
					payload.AddField(mustHex(f.Data), f.Type)
				}

				assert.Equal(t, payload.data, mustHex(session.Messages[messageIndex].Payload))

				hsm, cs1r, cs2r = sender.WriteMessage(nil, payload.data)

				pkt.data = append(pkt.data, hsm...)
				binary.BigEndian.PutUint16(pkt.data, uint16(len(pkt.data)-2))

				assert.Equal(t, pkt.data, mustHex(session.Messages[messageIndex].Packet))
			}
		}
	}*/
}

func Unpacket(t *testing.T, packet []byte) []byte {
	assert.Equal(t, len(packet) > 4, true)

	pl := binary.BigEndian.Uint16(packet)
	assert.Equal(t, int(pl), len(packet[2:]))

	return packet[2:]
}

func mustHex(str string) []byte {
	res, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	if len(res) == 0 {
		return nil
	}
	return res
}
