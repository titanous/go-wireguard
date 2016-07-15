package wireguard

import (
	"net"
	"time"
)

// A Peer is a remote endpoint that can be communicated with via an Interface.
type Peer struct {
	// PublicKey is the static Curve25519 public key of the peer. It must be
	// exactly 32 bytes.
	PublicKey []byte

	// AllowedIPs is the list of IP networks that will be routed to and accepted
	// from the peer.
	AllowedIPs []*net.IPNet

	// Endpoint is the network address that packets destined for the peer will
	// be sent to. If it is nil, packets destined for this peer will not be
	// routable until an incoming handshake is received.
	Endpoint *net.UDPAddr

	// PersistentKeepaliveInterval, if non-zero, is the number of seconds
	// between keep-alive packets sent to the peer.
	PersistentKeepaliveInterval int

	// LastHandshake is the timestamp of the last successful handshake with the
	// peer. This field is read-only.
	LastHandshake time.Time

	// RxBytes is the number of bytes received from the peer. This field is
	// read-only.
	RxBytes int64

	// TxBytes is the number of bytes transmitted to the peer. This field is
	// read-only.
	TxBytes int64
}

type peer struct {
	handshake noiseHandshake
}

func (p *peer) public() *Peer {
	return nil
}

func (p *peer) updateLatestAddr(a *net.UDPAddr) {

}

func (p *peer) rxStats(n int) {

}

func (p *peer) timerAnyAuthenticatedPacketReceived() {

}

func (p *peer) timerAnyAuthenticatedPacketTraversal() {

}

func (p *peer) timerEphemeralKeyCreated() {

}

func (p *peer) timerHandshakeComplete() {

}
