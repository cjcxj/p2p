package p2p

// recordingListener captures events for assertions in other sdk tests.
type recordingListener struct {
	events []int
	peers  []string
	data   []string
}

func (l *recordingListener) OnEvent(event int, peerID string, data []byte) {
	l.events = append(l.events, event)
	l.peers = append(l.peers, peerID)
	l.data = append(l.data, string(data))
}
