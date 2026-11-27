//go:build race

package punch

// raceEnabled tells the simulated-network tests they are running with the race
// detector, where every punching round costs several times more CPU and a
// wall-clock deadline would otherwise stand for far fewer spray rounds.
const raceEnabled = true
