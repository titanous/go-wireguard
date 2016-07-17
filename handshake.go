package wireguard

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"github.com/flynn/wireguard-go/internal/skip32"
	"github.com/flynn/wireguard-go/internal/tai64n"
)

const (
	handshakeStateConsumedInitiation = iota
	handshakeStateCreatedResponse
	handshakeStateCreatedInitiation
	handshakeStateConsumedResponse
	handshakeStateZeroed
)

func init() {
	key := make([]byte, 10)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}

	// The SKIP32 cipher obfuscates the counter, which is used in packet headers
	// to to identify the handshake, so that it cannot be easily predicted and
	// does not trivially expose the actual count of handshakes.
	handshakeCounterCipher, _ = skip32.New(key)
}

var keypairCounter uint64
var handshakeCounter uint32
var handshakeCounterCipher *skip32.Skip32

func getHandshakeID() uint32 {
	return handshakeCounterCipher.Obfus(atomic.AddUint32(&handshakeCounter, 1))
}

type noiseHandshake struct {
	sync.RWMutex

	senderIndex uint32
	remoteIndex uint32

	latestTimestamp tai64n.TAI64N

	lastInitiationConsumption time.Time

	hs *noise.HandshakeState

	state int

	sendingCipher   noise.Cipher
	receivingCipher noise.Cipher

	remoteStatic [32]byte

	peer *peer
}

func (h *noiseHandshake) clear() {
	h.remoteIndex = 0
	h.senderIndex = 0
	h.hs = nil
	h.sendingCipher = nil
	h.receivingCipher = nil
	h.state = handshakeStateZeroed
}

type noiseKeypair struct {
	initiator bool

	internalID  uint64
	senderIndex uint32
	remoteIndex uint32

	sending   noise.Cipher
	receiving noise.Cipher

	peer *peer
}

type noiseKeypairs struct {
	previous, current, next *noiseKeypair
	sync.RWMutex
}

var (
	noiseCiphersuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	noisePrologue    = []byte("WireGuard v0 zx2c4 Jason@zx2c4.com")

	errUnknownPeer      = errors.New("wireguard: peer is unknown")
	errUnknownHandshake = errors.New("wireguard: handshake is unknown")
	errAttack           = errors.New("wireguard: handshake is considered an attack")
	errNoIdentity       = errors.New("wireguard: no identity is configured")
	errInvalidState     = errors.New("wireguard: handshake is in invalid state")
)

func (f *Interface) handshakeCreateInitiation(handshake *noiseHandshake) []byte {
	f.identityMtx.RLock()
	defer f.identityMtx.RUnlock()

	if len(f.staticKey.Private) == 0 {
		return nil
	}

	handshake.Lock()
	defer handshake.Unlock()

	handshake.hs = noise.NewHandshakeState(noise.Config{
		CipherSuite:   noiseCiphersuite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      noisePrologue,
		PresharedKey:  f.presharedKey,
		StaticKeypair: f.staticKey,
		PeerStatic:    handshake.remoteStatic[:],
	})

	res := make([]byte, 5, messageHandshakeInitiationLen)
	res[0] = byte(messageHandshakeInitiation)

	var taiBuf [12]byte
	tai64n.Now().WriteStorage(taiBuf[:])

	handshake.hs.WriteMessage(res, taiBuf[:])
	handshake.senderIndex = getHandshakeID()
	binary.LittleEndian.PutUint32(res[1:], handshake.senderIndex)

	handshake.state = handshakeStateCreatedInitiation

	f.handshakesMtx.Lock()
	f.handshakes[handshake.senderIndex] = handshake
	f.handshakesMtx.Unlock()

	return res
}

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
	peer.handshake.remoteIndex = binary.LittleEndian.Uint32(data[1:])
	peer.handshake.lastInitiationConsumption = time.Now()
	peer.handshake.state = handshakeStateConsumedInitiation
	peer.handshake.Lock()

	return peer, nil
}

func (f *Interface) handshakeCreateResponse(handshake *noiseHandshake) []byte {
	handshake.Lock()
	defer handshake.Unlock()

	if handshake.state != handshakeStateConsumedInitiation {
		return nil
	}

	res := make([]byte, 9, messageHandshakeResponseLen)
	res[0] = byte(messageHandshakeResponse)
	binary.LittleEndian.PutUint32(res[5:], handshake.remoteIndex)
	res, cs1, cs2 := handshake.hs.WriteMessage(res[9:], nil)
	handshake.receivingCipher = cs1.Cipher()
	handshake.sendingCipher = cs2.Cipher()
	handshake.senderIndex = getHandshakeID()
	binary.LittleEndian.PutUint32(res[1:], handshake.senderIndex)

	f.handshakesMtx.Lock()
	f.handshakes[handshake.senderIndex] = handshake
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

	receiverIndex := binary.LittleEndian.Uint32(data[5:])
	f.handshakesMtx.Lock()
	handshake, ok := f.handshakes[receiverIndex]
	f.handshakesMtx.Unlock()
	if !ok {
		return nil, errUnknownHandshake
	}
	handshake.Lock()
	defer handshake.Unlock()

	if handshake.state != handshakeStateCreatedInitiation {
		return nil, errInvalidState
	}

	_, cs1, cs2, err := handshake.hs.ReadMessage(nil, data[9:])
	if err != nil {
		return nil, err
	}
	handshake.receivingCipher = cs2.Cipher()
	handshake.sendingCipher = cs1.Cipher()
	handshake.state = handshakeStateConsumedResponse
	handshake.remoteIndex = binary.LittleEndian.Uint32(data[1:])

	return handshake.peer, nil
}

func (f *Interface) handshakeBeginSession(handshake *noiseHandshake, keypairs *noiseKeypairs, initiator bool) {
	handshake.Lock()
	defer handshake.Unlock()
	keypair := &noiseKeypair{
		internalID:  atomic.AddUint64(&keypairCounter, 1),
		remoteIndex: handshake.remoteIndex,
		senderIndex: handshake.senderIndex,
		peer:        handshake.peer,
		initiator:   initiator,
		receiving:   handshake.receivingCipher,
		sending:     handshake.sendingCipher,
	}

	f.handshakesMtx.Lock()
	delete(f.handshakes, handshake.senderIndex)
	f.handshakesMtx.Unlock()
	handshake.clear()

	keypairs.Lock()
	if initiator {
		if keypairs.next != nil {
			keypairs.previous = keypairs.next
			keypairs.next = nil
		} else {
			keypairs.previous = keypairs.current
		}
		keypairs.current = keypair
	} else {
		keypairs.next = keypair
		keypairs.previous = nil
	}
	keypairs.Unlock()

	f.keypairsMtx.Lock()
	f.keypairs[keypair.senderIndex] = keypair
	f.keypairsMtx.Unlock()
}

func (f *Interface) receivedWithKeypair(keypairs *noiseKeypairs, receivedKeypair *noiseKeypair) (next bool) {
	keypairs.Lock()
	defer keypairs.Unlock()
	if receivedKeypair == keypairs.next {
		keypairs.previous = keypairs.current
		keypairs.current = receivedKeypair
		keypairs.next = nil
		next = true
	}
	return
}
