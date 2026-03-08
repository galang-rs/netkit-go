package proxy

import (
	"io"
	"net"
)

// PeekedConn wraps a net.Conn and allows re-reading already peeked data
type PeekedConn struct {
	net.Conn
	Peeked []byte
	offset int
}

func (c *PeekedConn) Read(b []byte) (n int, err error) {
	if c.offset < len(c.Peeked) {
		n = copy(b, c.Peeked[c.offset:])
		c.offset += n
		return n, nil
	}
	return c.Conn.Read(b)
}

func (c *PeekedConn) WriteTo(w io.Writer) (n int64, err error) {
	if c.offset < len(c.Peeked) {
		m, err := w.Write(c.Peeked[c.offset:])
		n = int64(m)
		if err != nil {
			return n, err
		}
		c.offset = len(c.Peeked)
	}
	m, err := io.Copy(w, c.Conn)
	return n + m, err
}
