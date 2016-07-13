package wireguard

type messageType byte

const (
	messageInvalid             messageType = 0
	messageHandshakeInitiation messageType = 1
	messageHandshakeResponse   messageType = 2
	messageHandshakeCookie     messageType = 3
	messageData                messageType = 4

	messageHandshakeInitiationLen = 1 /*type*/ + 4 /*sender*/ + 32 /*ephemeral*/ + 32 /*static*/ + 12 /*timestamp*/ + 16 /*mac1*/ + 16 /*mac2*/

	messageHandshakeResponseLen = 1 /*type*/ + 4 /*sender*/ + 4 /*receiver*/ + 32 /*ephemeral*/ + 16 /*mac1*/ + 16 /*mac2*/

	messageHandshakeCookieLen = 1 /*type*/ + 4 /*receiver*/ + 32 /*salt*/ + 16 /*cookie*/

	messageDataMinLen = 1 /*type*/ + 4 /*receiver*/ + 8 /*counter*/ + 16 /*tag*/

	messageMinLen = 1 /*type*/

	messageOptimalAlignment = 32
	messagePaddingMultiple  = 16
)

func checkMessageType(b []byte) messageType {
	if len(b) < messageMinLen {
		return messageInvalid
	} else if b[0] == byte(messageData) && len(b) >= messageDataMinLen {
		return messageData
	} else if b[0] == byte(messageHandshakeInitiation) && len(b) == messageHandshakeInitiationLen {
		return messageHandshakeInitiation
	} else if b[0] == byte(messageHandshakeResponse) && len(b) == messageHandshakeResponseLen {
		return messageHandshakeResponse
	} else if b[0] == byte(messageHandshakeCookie) && len(b) == messageHandshakeCookieLen {
		return messageHandshakeCookie
	} else {
		return messageInvalid
	}
}
