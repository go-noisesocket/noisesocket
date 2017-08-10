# Noise Socket Meets Virgil PKI

This example shows how a PKI can be added to NoiseSocket to implement mutual auth.

Usage:

Client:
    client -email=client@example.com -serverMail=server@example.com
    
Server:
    server -email=server@example.com -clientMail=client@example.com    

it will ask you to enter confirmation code on the first start

1. Setup
---------

First, a Global Virgil Card must be created for both server and client. It is done by using Virgil API and requires your email

```go
func InitVirgilCard(email string){

}
```

First, this function will generate a random public/private keypair and save your private key to a file.

Then it will ask for the confirmation code you received and will register your card on the Virgil card service.

**Your private key will be used to sign NoiseSocket's static key once the app starts**

2. Handshake
------------

The signature for NoiseSocket public key is transmitted together with the email you used for you Virgil Card inside the 
NoiseSocket handshake as a json object:

```js
{
    identity : "my_mail@example.com",
    signature : "base64String"
}
```

3. Authentication
-------------
The other peer takes NoiseSocket public key, extracts signature and identity and requests your card from Virgil Card Service.

NoiseSocket provides VerifyCallback function template which can be used for that.

An example of such function which validates server's public key's signature using Virgil Cards:

```go
func VerifyCallback(publicKey []byte, data []byte) error {

	identity, signature, err := v.GetIdentityAndSignature(data)

	if err != nil {
		return err
	}

	if identity != serverMail {
		return errors.New("invalid identity")
	}

	return v.ValidateSignature(publicKey, signature, identity)
}


func ValidateSignature(data, signature virgilapi.Buffer, identity string) (err error) {

	cards, ok := identityCardsMap[identity]

	if !ok {
		api, _ := virgilapi.New("")

		cards, err = api.Cards.FindGlobal("email", identity)

		identityCardsMap[identity] = cards
	}

	for _, card := range cards {
		if ok, err = card.Verify(data, signature); ok {
			return nil
		}
	}

	return errors.New("could not validate signature for the given identity")
}
```


There's a cache which is used to avoid requesting cards every time a new connection made.


Let us know what you think of it!

