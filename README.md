# Noise Socket Go - a [Noise Socket](https://github.com/noisesocket/spec) implementation in Go

go get -u gopkg.in/noisesocket.v0

See [sample](sample) folder for an example of HTTPS client and server implementations

Supported cryptoprimitives: 
-------------------------
* Noise protocols: XX & IK 
* Symmetric chiphers: AES256-GCM, ChachaPoly1305 
* Hashes: SHA256, SHA512, Blake2b, Blake2s 
* DH: Curve25519


Negotiation data structure: 
-------------------------
2 bytes: version (currently 00 01)
1 byte: DH
1 byte: Cipher
1 byte: Hash
1 byte: Template

Values are as follows:

	NOISE_DH_CURVE25519 = 1

	NOISE_CIPHER_CHACHAPOLY = 1
	NOISE_CIPHER_AESGCM     = 2

	NOISE_HASH_BLAKE2s = 1
	NOISE_HASH_BLAKE2b = 2
	NOISE_HASH_SHA256  = 3
	NOISE_HASH_SHA512  = 4

	NOISE_PATTERN_XX = 9
	NOISE_PATTERN_IK = 14