package room

// PostStore is the interface for post storage backends.
// The default in-memory implementation uses a circular buffer (MemoryPostStore).
type PostStore interface {
	// AddPost adds a post to the store. In bounded implementations, the oldest
	// post may be evicted when at capacity.
	AddPost(p *PostInfo) error

	// GetPostsSince returns posts with Timestamp strictly greater than the
	// given timestamp, ordered oldest to newest.
	GetPostsSince(timestamp uint32) []*PostInfo

	// Count returns the number of stored posts.
	Count() int

	// Clear removes all posts.
	Clear()
}
