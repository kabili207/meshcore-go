package router

// Loop detection levels for flood forwarding. When enabled, the router counts
// how many times its own hash appears in a packet's path and drops packets
// that exceed the threshold for the current hash size and detection level.
const (
	LoopDetectOff      = 0
	LoopDetectMinimal  = 1
	LoopDetectModerate = 2
	LoopDetectStrict   = 3
)

// loopThresholds[level][hashSize-1] gives the maximum allowed self-hash
// occurrences before a packet is considered looped. Level 0 (off) is unused.
var loopThresholds = [4][3]int{
	{0, 0, 0}, // off (never consulted)
	{4, 2, 1}, // minimal
	{2, 1, 1}, // moderate
	{1, 1, 1}, // strict
}

// detectLoop returns true if the path contains enough occurrences of selfHash
// to indicate a routing loop at the given detection level.
func detectLoop(path []byte, selfHash []byte, hashSize int, level int) bool {
	if level <= LoopDetectOff || level > LoopDetectStrict {
		return false
	}
	if hashSize < 1 || hashSize > 3 || len(selfHash) < hashSize {
		return false
	}

	threshold := loopThresholds[level][hashSize-1]
	count := 0

	for i := 0; i+hashSize <= len(path); i += hashSize {
		match := true
		for j := 0; j < hashSize; j++ {
			if path[i+j] != selfHash[j] {
				match = false
				break
			}
		}
		if match {
			count++
			if count >= threshold {
				return true
			}
		}
	}
	return false
}
