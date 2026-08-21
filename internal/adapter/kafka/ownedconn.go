package kafka

import "net"

// ownedConn is the ADR 0021 ownership rules, once.
//
// Two session types in this package hold a connection, and a third will when
// authentication lands. The rules — one owner at a time, one transfer, Close
// safe to defer and safe to repeat — are a security property rather than
// convenience plumbing, so they exist in one place where they can be read and
// tested once instead of being retyped per type.
//
// It is an embedded struct rather than an interface: there is one
// implementation, and the architecture asks for concrete types until a second
// one exists.
type ownedConn struct {
	conn   net.Conn
	taken  bool
	closed bool
}

// Available reports whether the connection is still here to take.
func (o *ownedConn) Available() bool {
	return o.conn != nil && !o.taken && !o.closed
}

// TakeConn transfers ownership of the connection to the caller.
//
// A caller that receives true owns the connection and must close it; nothing in
// this package will.
func (o *ownedConn) TakeConn() (net.Conn, bool) {
	if !o.Available() {
		return nil, false
	}
	o.taken = true
	return o.conn, true
}

// Close releases the connection if it is still owned here. It is idempotent and
// does nothing after a transfer.
func (o *ownedConn) Close() error {
	if o.conn == nil || o.taken || o.closed {
		return nil
	}
	o.closed = true
	return o.conn.Close()
}
