Reverse proxy demo

1) go run proxy.go
2) Navigate to http://localhost:1080. The content will be served through NoiseSocket-powered connection

3) Navigate to http://localhost:1080/status 
 There you'll see the protocol and message index, chosen by Server as well as current connection's handshake hash and server's and proxy's static public keys
 Same handshake should be present in response's headers. They are added by proxy