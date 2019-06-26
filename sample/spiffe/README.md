# NoiseSocket with SPIFFE

This example shows how [NoiseSocket](https://noisesocket.org/) and [SPIFFE](https://spiffe.io/) can be used together to
implement mutual authentication and authorization based on SPIFFE IDs.

The example reproduces [`SIMPLE Verification`](https://github.com/spiffe/spiffe-example/tree/master/simple_verification)
example, but it employs `NoiseSocket` instead of `TLS`.

## Warning

This is experimental code for demonstration purposes only, don't use it in production.

## Description

There are two entities (workloads within SPIFFE terminology) called `blog` and `database`
that have already gotten their [X.509 SVID](https://github.com/spiffe/spiffe/blob/master/standards/X509-SVID.md) via the ` SPIFFE Workload API`.
In an X.509 SVID, the SPIFFE ID is set as a URI type in the Subject Alternative Name extension of an X.509 certificate.
The SVIDs are located in the corresponding `client/keys` and `server/keys` directories and contain special SPIFFE ID values that identify the entities.

SVIDs provide the following.
First, they are used to [authenticate](https://noiseprotocol.org/noise.html#security-considerations) Noise's static public keys within [`XX` pattern](http://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental) via signing. 
Second, `NoiseSocket` connections are accepted or rejected based on allowed SPIFFE IDs.

## Usage

1. Run the server:
    ```
    go run main.go --allow-uri=spiffe://blog.dev.example.org/path/service
    ```

2. Run the client:
    ```
    go run main.go
    ```


## Scenario 

### Setup

The scenario simulates the presence of a blog service connecting to a database service
The database service allows ingress connection based on SPIFFE ID.
It is suggested that the services have already had SPIFFE IDs as X.509 certificates.

X.509 SVID private key will be used to sign NoiseSocket's static key during the handshake.

### Handshake

The signature for `NoiseSocket` public static key is transmitted together with an entity certificate inside the
`NoiseSocket` handshake as a `json` object:

```js
{
    Certificate : "certificate",
    Signature   : "signature"
}
```

### Authentication

The other peer takes `NoiseSocket` public static key, extracts signature and X.509 SVID and verifies their authenticity.
NoiseSocket provides `VerifyCallback` function template which can be used for that.
After that, the server validates ingress SPIFFE URI according to the list of allowed SPIFFE IDs.
