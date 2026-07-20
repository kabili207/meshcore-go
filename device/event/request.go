package event

// AnonRequestReceived fires after an anonymous request (ANON_REQ) packet is
// successfully decrypted. Anonymous requests use an ephemeral keypair and do
// not require a pre-existing contact relationship. This is primarily used for
// login/authentication flows (e.g., room server login).
type AnonRequestReceived struct {
	Event
	Reply ReplyContext

	// EphemeralPubKey is the sender's ephemeral Ed25519 public key used for
	// this single request. The ReplyContext.SharedSecret is derived from this
	// key and the node's private key.
	EphemeralPubKey [32]byte

	// Plaintext is the raw decrypted payload. The format depends on the
	// application protocol — for room server login this contains:
	// timestamp(4) + syncSince(4) + password(null-terminated).
	// Consumers parse this according to their protocol.
	Plaintext []byte
}

// RequestReceived fires after an addressed REQ packet is successfully decrypted
// and parsed. REQ packets are used for structured queries such as stats, telemetry,
// access lists, and keepalive signals.
type RequestReceived struct {
	Event
	Reply ReplyContext

	// RequestType identifies the type of request. See codec.ReqType* constants:
	// ReqTypeLogin, ReqTypeGetStats, ReqTypeKeepalive, ReqTypeGetTelemetry,
	// ReqTypeGetMinMaxAvg, ReqTypeGetAccessList, ReqTypeGetNeighbors, ReqTypeGetOwnerInfo.
	RequestType uint8

	// RequestData is the request-specific data following the type byte.
	// Format depends on RequestType. May be empty.
	RequestData []byte

	// Tag is the request's timestamp field, reflected in responses so the
	// sender can match responses to requests.
	Tag uint32
}

// ResponseReceived fires after an addressed RESPONSE packet is successfully
// decrypted. Responses are replies to REQ or ANON_REQ packets.
type ResponseReceived struct {
	Event
	Reply ReplyContext

	// Tag is the response tag, matching the Tag from the original request.
	Tag uint32

	// Content is the response payload following the tag. Format depends
	// on the original request type.
	Content []byte
}

// LoginResponse fires when a server accepts a login (RESP_SERVER_LOGIN_OK)
// following a SendLogin. The embedded Event's From field is the server that
// accepted the login.
type LoginResponse struct {
	Event

	// Permissions is the ACL permission byte the server granted (see
	// codec.PermACL* constants).
	Permissions uint8

	// IsAdmin is true if the server granted admin access.
	IsAdmin bool

	// ServerTimestamp is the server's clock at login (the response tag).
	ServerTimestamp uint32

	// FirmwareVerLevel is the server's firmware version level, used by clients
	// to gate which admin features they offer.
	FirmwareVerLevel uint8
}

// TelemetryResponse fires when a peer answers a SendTelemetryReq. The embedded
// Event's From field is the responding peer.
type TelemetryResponse struct {
	Event

	// Data is the CayenneLPP-encoded telemetry payload. Decoding is the
	// application's responsibility.
	Data []byte
}
