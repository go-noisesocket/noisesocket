package noisesocket

import (
	"net"

	"github.com/flynn/noise"
)

// A listener implements a network listener (net.Listener) for TLS connections.
type listener struct {
	net.Listener
	key noise.DHKey
}

// Accept waits for and returns the next incoming connection.
// The returned connection is of type *Conn.
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &Conn{
		conn:    c,
		myKeys:  l.key,
		padding: 1024,
	}, nil
}

// Listen creates a TLS listener accepting connections on the
// given network address using net.Listen.
func Listen(laddr string, key noise.DHKey) (net.Listener, error) {

	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	return &listener{
		Listener: l,
		key:      key,
	}, nil
}

func Dial(addr string, key noise.DHKey, serverKey []byte) (*Conn, error) {
	rawConn, err := new(net.Dialer).Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	return &Conn{
		conn:     rawConn,
		myKeys:   key,
		PeerKey:  serverKey,
		isClient: true,
		padding:  1024,
	}, nil
}
