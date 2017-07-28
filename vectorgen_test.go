package noisesocket

import "testing"

type Vector struct {
	Name             string     `json:"name"`
	Prologue         string     `json:"init_prologue"`
	InitStatic       string     `json:"init_static"`
	InitEphemeral    string     `json:"init_ephemeral"`
	InitRemoteStatic string     `json:"init_remote_static"`
	RespStatic       string     `json:"resp_static"`
	RespEphemeral    string     `json:"resp_ephemeral"`
	InitialMessage   string     `json:"initial_message"`
	Protocols        []string   `json:"protocols"`
	Sessions         []*Session `json:"sessions"`
}

type Session struct {
	Index         byte       `json:"index"`
	Pattern       string     `json:"pattern"`
	Dh            string     `json:"dh"`
	Cipher        string     `json:"cipher"`
	Hash          string     `json:"hash"`
	HandshakeHash string     `json:"handshake_hash"`
	Messages      []*Message `json:"messages"`
}

type Message struct {
	Payload string         `json:"payload"`
	Fields  []*VectorField `json:"fields"`
	Packet  string         `json:"buffer,omitempty"`
}

type VectorField struct {
	Type uint16
	Data string
}

func TestGenerateVectors(t *testing.T) {

	/*is, rs, ie, re := make([]byte, 0, 32), make([]byte, 0, 32), make([]byte, 0, 32), make([]byte, 0, 32)
	for i := byte(0); i < 32; i++ {
		ie = append(ie, i%2)
		re = append(re, i%3)
		is = append(is, i%4)
		rs = append(rs, i%5)
	}

	ki := noise.DH25519.GenerateKeypair(bytes.NewBuffer(is))
	kr := noise.DH25519.GenerateKeypair(bytes.NewBuffer(rs))

	clientCert := []byte(`{owner:"alice@client.com"}`)
	serverCert := []byte(`{owner:"bob@server.com"}`)

	vec := &Vector{
		Name:             "NoiseSocket",
		InitEphemeral:    hex.EncodeToString(ie),
		InitStatic:       hex.EncodeToString(is),
		InitRemoteStatic: hex.EncodeToString(kr.Public),
		RespEphemeral:    hex.EncodeToString(re),
		RespStatic:       hex.EncodeToString(rs),
	}

	pkt := new(buffer)
	pkt.AddField(clientCert, MessageTypeCustomCert)

	ihm, prologue, iStates, err := ComposeInitiatorHandshakeMessage(ki, kr.Public, pkt.data, ie)
	assert.NoError(t, err)
	vec.Prologue = hex.EncodeToString(prologue)

	for _, pattern := range []noise.HandshakePattern{noise.HandshakeXX, noise.HandshakeIK} {

		for _, csp := range protoCipherPriorities[pattern.Name] {
			cfg := handshakeConfigs[csp]
			vec.Protocols = append(vec.Protocols, fmt.Sprintf("%s", cfg.Name))

		}
	}

	pkt = InitializePacket()
	pkt.data = append(pkt.data, ihm...)
	binary.BigEndian.PutUint16(pkt.data, uint16(len(ihm)))

	vec.InitialMessage = hex.EncodeToString(pkt.data)

	//sequetially choose sub-message from the first message
	for i, istate := range iStates {
		parsedPayload, rstate, cfg, msgIndex, err := ParseHandshake(kr, ihm, i, re)
		assert.NoError(t, err)

		sess := &Session{
			Index:   msgIndex,
			Pattern: cfg.Pattern.Name,
			Dh:      cfg.DH.DHName(),
			Cipher:  cfg.Cipher.CipherName(),
			Hash:    cfg.Hash.HashName(),
		}
		vec.Sessions = append(vec.Sessions, sess)

		msg := &Message{}

		if len(parsedPayload) > 0 {

			//server reads client's message
			fields, err := parseMessageFields(parsedPayload)
			assert.NoError(t, err)

			msg = &Message{
				Payload: hex.EncodeToString(parsedPayload),
				Fields:  fieldsToVector(fields),
			}

		}

		sess.Messages = append(sess.Messages, msg)

		pkt = InitializePacket() // 2 bytes for length

		if len(rstate.PeerStatic()) > 0 { //if we answer to IK, add one extra byte used for Noise pipes
			pkt.resize(len(pkt.data) + 2)
			pkt.data[len(pkt.data)-2] = msgIndex
		} else {
			pkt.resize(len(pkt.data) + 1)
			pkt.data[len(pkt.data)-1] = msgIndex
		}

		var cs1i, cs2i, cs1r, cs2r *noise.CipherState
		var hsm []byte
		payload := new(buffer)
		payload.AddField(serverCert, MessageTypeCustomCert)

		//server responds
		hsm, cs1r, cs2r = rstate.WriteMessage(nil, payload.data)
		pkt.data = append(pkt.data, hsm...)
		binary.BigEndian.PutUint16(pkt.data, uint16(len(pkt.data)-2))

		msg = &Message{
			Packet: hex.EncodeToString(pkt.data),
		}
		sess.Messages = append(sess.Messages, msg)
		sender := rstate
		receiver := istate

		//loop until handshake is done
		for {

			parsedPayload, cs1i, cs2i, err = receiver.ReadMessage(nil, hsm)
			assert.NoError(t, err)

			if len(parsedPayload) > 0 {
				msg.Payload = hex.EncodeToString(parsedPayload)
				fields, err := parseMessageFields(parsedPayload)
				assert.NoError(t, err)

				msg.Fields = fieldsToVector(fields)
			}

			if cs1r != nil && cs2r != nil && cs1i != nil && cs2i != nil {
				sess.HandshakeHash = hex.EncodeToString(receiver.ChannelBinding())
				for j := 0; j < 2; j++ {
					di := make([]byte, 11)
					dr := make([]byte, 13)

					rand.Read(di)
					rand.Read(dr)

					pkti := InitializePacket()
					pkti.AddField(di, MessageTypeData)
					pkti.AddPadding(10, 0)

					pktr := InitializePacket()
					pktr.AddField(dr, MessageTypeData)
					pktr.AddPadding(10, 0)

					msg = &Message{
						Payload: hex.EncodeToString(pkti.data[2:]),
					}
					pkti.data = cs1i.Encrypt(pkti.data[:2], nil, pkti.data[2:])
					binary.BigEndian.PutUint16(pkti.data, uint16(len(pkti.data)-2))

					msg.Packet = hex.EncodeToString(pkti.data)
					//fmt.Println(hex.EncodeToString(pkti.data))

					dr, err = cs1r.Decrypt(pkti.data[:0], nil, pkti.data[2:])
					assert.NoError(t, err)
					fields, err := parseMessageFields(dr)

					msg.Fields = fieldsToVector(fields)

					sess.Messages = append(sess.Messages, msg)

					msg = &Message{
						Payload: hex.EncodeToString(pktr.data[2:]),
					}

					pktr.data = cs2r.Encrypt(pktr.data[:2], nil, pktr.data[2:])
					binary.BigEndian.PutUint16(pktr.data, uint16(len(pktr.data)-2))

					msg.Packet = hex.EncodeToString(pktr.data)
					//fmt.Println(hex.EncodeToString(pktr.data))
					di, err = cs2i.Decrypt(pktr.data[:0], nil, pktr.data[2:])
					assert.NoError(t, err)

					fields, err = parseMessageFields(di)

					msg.Fields = fieldsToVector(fields)

					sess.Messages = append(sess.Messages, msg)

				}

				break

			} else {
				sender, receiver = receiver, sender

				pkt = InitializePacket() // 2 bytes for length

				payload = new(buffer)
				payload.AddField(clientCert, MessageTypeCustomCert)

				hsm, cs1r, cs2r = sender.WriteMessage(nil, payload.data)
				pkt.data = append(pkt.data, hsm...)
				binary.BigEndian.PutUint16(pkt.data, uint16(len(pkt.data)-2))
				msg = &Message{
					Packet: hex.EncodeToString(pkt.data),
				}
				sess.Messages = append(sess.Messages, msg)

			}

		}
	}
	v, _ := json.Marshal(vec)
	fmt.Printf("%s\n", v)*/

}

func InitializePacket() *buffer {
	block := new(buffer)
	block.resize(uint16Size)
	return block
}
