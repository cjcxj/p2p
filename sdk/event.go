package p2p

// Event identifiers passed to Listener.OnEvent.
const (
	// EventStateChanged: data carries the new session state string
	// ("connecting", "connected", "closed", "failed").
	EventStateChanged = 1
	// EventPeerJoined: a peer entered the room; data is the peer id.
	EventPeerJoined = 2
	// EventPeerLeft: a peer left the room; data is the peer id.
	EventPeerLeft = 3
	// EventPeerConnected: a peer became reachable; data carries the
	// transport used ("punched").
	EventPeerConnected = 4
	// EventData: data is an application payload from peerID.
	EventData = 5
	// EventError: data carries an error message.
	EventError = 6
	// EventDebug: data carries a verbose hole-punching flow message (only
	// when Config.Debug is enabled).
	EventDebug = 7
	// EventPathChanged: an already-connected peer switched transport; data
	// carries the new transport ("punched").
	EventPathChanged = 8
)

// Session states reported through EventStateChanged.
const (
	StateConnecting = "connecting"
	StateConnected  = "connected"
	StateClosed     = "closed"
	StateFailed     = "failed"
)

// Transports reported through EventPeerConnected. Pure P2P: a connected peer is
// reached by a punched direct link only -- there is no relay transport.
const (
	TransportPunched = "punched"
)

// Listener receives asynchronous events from a Session. The implementation
// must not call back into the Session from inside OnEvent.
type Listener interface {
	OnEvent(event int, peerID string, data []byte)
}
