# Noise Socket Go - a [Noise Socket](https://github.com/noisesocket/spec) implementation in Go

go get -u gopkg.in/noisesocket.v0

See [sample](sample) folder for an example of HTTPS client and server implementations

Supported cryptoprimitives: 
-------------------------
* Noise protocols: XX & IK 
* Symmetric chiphers: AES256-GCM, ChachaPoly1305 
* Hashes: SHA256, SHA512, Blake2b, Blake2s 
* DH: Curve25519
