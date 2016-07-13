package wireguard

import (
	"net"
)

type UDPConn interface {
	ReadFromUDP(b []byte) (int, *net.UDPAddr, error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	Close() error
}

type packet struct {
	addr *net.UDPAddr
	data []byte
}

func (f *Interface) acceptOutsidePackets() {
	for {
		buf := make([]byte, mtu)
		n, addr, err := f.outside.ReadFromUDP(buf)
		if err != nil {
			// TODO: figure out what kind of errors can be returned
		}
		buf = buf[:n]
		f.receiveOutsidePacket(packet{addr, buf})
	}
}

func (f *Interface) receiveOutsidePacket(p packet) {
	switch checkMessageType(p.data) {
	case messageHandshakeInitiation, messageHandshakeResponse, messageHandshakeCookie:
		// queue handshake
	case messageData:
		// queue for data processing
	default:
		// log invalid packet
	}
}

func (f *Interface) receiveHandshakePacket(typ messageType, p packet) {
	// TODO: cookie check
	var peer *peer
	var err error

	switch typ {
	case messageHandshakeInitiation:
		peer, err = f.handshakeConsumeInitiation(p.data)
		if err != nil {
			// TODO: log error
			return
		}
		peer.updateLatestAddr(p.addr)
		f.handshakeSendResponse(peer)
	case messageHandshakeResponse:
		peer, err = f.handshakeConsumeResponse(p.data)
		if err != nil {
			// TODO: log error
			return
		}
		peer.timerEphemeralKeyCreated()
		peer.timerHandshakeComplete()
	}

	peer.rxStats(len(p.data))
	peer.timerAnyAuthenticatedPacketReceived()
	peer.timerAnyAuthenticatedPacketTraversal()
	peer.updateLatestAddr(p.addr)
}

func (f *Interface) handshakeConsumeInitiation(data []byte) (*peer, error) {
	f.identityMtx.RLock()
	defer f.identityMtx.RUnlock()

	if f.

	return nil, nil
}

func (f *Interface) handshakeConsumeResponse(data []byte) (*peer, error) {
	return nil, nil
}

func (f *Interface) handshakeSendResponse(p *peer) {

}
