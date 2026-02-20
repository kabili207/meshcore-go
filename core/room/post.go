package room

import (
	"github.com/kabili207/meshcore-go/core"
)

const (
	// DefaultMaxPosts is the default capacity for the post store.
	// Firmware uses MAX_POSTS = 100.
	DefaultMaxPosts = 100
)

// PostInfo represents a message stored on the room server for client sync.
// Posts are added by clients and pushed to other clients via the sync loop.
type PostInfo struct {
	// Timestamp is the room's clock time when this post was stored.
	Timestamp uint32

	// SenderID is the public key of the client who sent this post.
	SenderID core.MeshCoreID

	// Content is the raw encrypted message content (addressed payload).
	Content []byte
}
