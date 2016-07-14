package wireguard

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"github.com/flynn/wireguard/internal/tai64n"
)

const (
	handshakeStateConsumedInitiation = iota
	handshakeStateCreatedResponse
)

var handshakeCounter uint32

type handshake struct {
	sync.RWMutex

	remoteIndex uint32

	latestTimestamp tai64n.TAI64N

	lastInitiationConsumption time.Time

	hs *noise.HandshakeState

	state int

	peer *peer
}

var noiseCiphersuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
var noisePrologue = []byte("WireGuard v0 zx2c4 Jason@zx2c4.com")

var errUnknownPeer = errors.New("wireguard: peer is unknown")
var errAttack = errors.New("wireguard: handshake is considered an attack")
var errNoIdentity = errors.New("wireguard: no identity is configured")

const minInitiationInterval = time.Second / 2

func (f *Interface) handshakeConsumeInitiation(data []byte) (*peer, error) {
	f.identityMtx.RLock()
	defer f.identityMtx.RUnlock()

	if len(f.staticKey.Private) == 0 {
		return nil, errNoIdentity
	}

	hs := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noiseCiphersuite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      noisePrologue,
		PresharedKey:  f.presharedKey,
		StaticKeypair: f.staticKey,
	})
	var taiBuf [12]byte
	tai, _, _, err := hs.ReadMessage(taiBuf[:0], data[5:])
	if err != nil {
		return nil, err
	}
	var t tai64n.TAI64N
	t.ReadStorage(tai)

	var s publicKey
	copy(s[:], hs.PeerStatic())
	f.peersMtx.RLock()
	peer, ok := f.peers[s]
	f.peersMtx.RUnlock()
	if !ok {
		return nil, errUnknownPeer
	}

	peer.handshake.RLock()
	replayAttack := !t.After(peer.handshake.latestTimestamp)
	floodAttack := !peer.handshake.lastInitiationConsumption.IsZero() && time.Now().Before(peer.handshake.lastInitiationConsumption.Add(minInitiationInterval))
	peer.handshake.RUnlock()
	if replayAttack || floodAttack {
		return nil, errAttack
	}

	peer.handshake.Lock()
	peer.handshake.hs = hs
	peer.handshake.latestTimestamp = t
	peer.handshake.remoteIndex = binary.BigEndian.Uint32(data[1:])
	peer.handshake.lastInitiationConsumption = time.Now()
	peer.handshake.state = handshakeStateConsumedInitiation
	peer.handshake.Lock()

	return peer, nil
}

func (f *Interface) handshakeCreateResponse(handshake *handshake) []byte {
	handshake.Lock()
	defer handshake.Unlock()

	if handshake.state != handshakeStateConsumedInitiation {
		return nil
	}

	res := make([]byte, 9, messageHandshakeResponseLen)
	res[0] = byte(messageHandshakeResponse)
	binary.BigEndian.PutUint32(res[5:], handshake.remoteIndex)
	res, _, _ = handshake.hs.WriteMessage(res[9:], nil)
	senderIndex := atomic.AddUint32(&handshakeCounter, 1)
	binary.BigEndian.PutUint32(res[1:], senderIndex)

	f.handshakesMtx.Lock()
	f.handshakes[senderIndex] = handshake
	f.handshakesMtx.Unlock()

	handshake.state = handshakeStateCreatedResponse

	return res
}

func (f *Interface) handshakeConsumeResponse(data []byte) (*peer, error) {
	f.identityMtx.RLock()
	defer f.identityMtx.RUnlock()

	if len(f.staticKey.Private) == 0 {
		return nil, errNoIdentity
	}

	return nil, nil
}
