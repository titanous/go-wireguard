package wireguard

import (
	"errors"
	"io"
)

// An InterfaceConfig is the configuration used to create an interface.
type InterfaceConfig struct {
	// Outside is the connection that will be used to send and receive encrypted
	// packets with peers. It will be closed if Close is called on the Interface.
	Outside UDPConn

	// Inside is the interface that will be used to read plaintext packets
	// destined for peers and write decrypted packets received from peers. Each
	// Read must return a single IP packet to send to a peer, and each Write
	// will provide a single received IP packet.
	Inside io.ReadWriter

	// PrivateKey holds the static Curve25519 private key for the interface. It
	// must be exactly 32 random bytes.
	PrivateKey []byte

	// PresharedKey holds an optional pre-shared key to use during handshakes.
	// If set, it must be exactly 32 random bytes.
	PresharedKey []byte

	// Peers is the initial set of peers that the interface will communicate
	// with.
	Peers []*Peer
}

func NewInterface(c InterfaceConfig) (*Interface, error) {
	if c.Outside == nil {
		return nil, errors.New("wireguard: Outside connection is nil")
	}
	if c.Inside == nil {
		return nil, errors.New("wireguard: Inside pipe is nil")
	}
	if len(c.PrivateKey) != 32 {
		return nil, errors.New("wireguard: PrivateKey must be exactly 32 bytes")
	}
	if c.PresharedKey != nil && len(c.PresharedKey) != 32 {
		return nil, errors.New("wireguard: when not nil, PresharedKey must be exactly 32 bytes")
	}

	return &Interface{
		outside:      c.Outside,
		inside:       c.Inside,
		privateKey:   c.PrivateKey,
		presharedKey: c.PresharedKey,
	}, nil
}

// An Interface communicates encrypted packets with peers.
type Interface struct {
	started bool

	outside UDPConn
	inside  io.ReadWriter

	identityMtx sync.RWMutex // protects staticKey and presharedKey
	staticKey *noise.DHKey
	presharedKey []byte

	peers []*Peer
}

// Run starts the interface and blocks until it is closed.
func (f *Interface) Run() error {
	if f.started {
		return errors.New("wireguard: the interface is already started")
	}

	return nil
}

// Close shuts down the interface.
func (f *Interface) Close() error {
	return nil
}

// SetPrivateKey changes the private key for the interface. It is safe to call
// while the interface is running.
func (f *Interface) SetPrivateKey(k []byte) error {
	if len(k) != 32 {
		return errors.New("wireguard: PrivateKey must be exactly 32 bytes")
	}
	return nil
}

// SetPresharedKey changes the pre-shared key for the interface.
func (f *Interface) SetPresharedKey(k []byte) error {
	if k != nil && len(k) != 32 {
		return errors.New("wireguard: PresharedKey must be exactly 32 bytes")
	}
	return nil
}

// SetPeers replaces all of the peers that the interface is configured for with
// a new list.
func (f *Interface) SetPeers(peers []*Peer) error {
	return nil
}

// GetPeers retrieves a list of all peers known to the interface.
func (f *Interface) GetPeers() []*Peer {
	return nil
}

// RemovePeer removes the peer identified with the public key pubkey from the
// interface configuration.
func (f *Interface) RemovePeer(pubkey []byte) error {
	return nil
}

// AddPeer adds a peer to the interface configuration. If the peer, identified
// by its public key, already exists, then all configuration will be replaced
// with the new fields.
func (f *Interface) AddPeer(p *Peer) error {
	return nil
}
