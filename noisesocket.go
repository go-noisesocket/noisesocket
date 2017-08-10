package noisesocket

import "net"

// A listener implements a network listener (net.Listener) for TLS connections.
type listener struct {
	net.Listener
	config *ConnectionConfig
}

// Accept waits for and returns the next incoming connection.
// The returned connection is of type *Conn.
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &Conn{
		conn:   c,
		config: *l.config,
	}, nil
}

// Listen creates a TLS listener accepting connections on the
// given network address using net.Listen.
func Listen(laddr string, config *ConnectionConfig) (net.Listener, error) {

	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	return &listener{
		Listener: l,
		config:   config,
	}, nil
}

func Dial(addr string, config *ConnectionConfig) (*Conn, error) {
	rawConn, err := new(net.Dialer).Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	config.isClient = true
	return &Conn{
		conn:   rawConn,
		config: *config,
	}, nil
}
