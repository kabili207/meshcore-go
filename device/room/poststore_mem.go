package room

import "sync"

// Compile-time assertion that MemoryPostStore implements PostStore.
var _ PostStore = (*MemoryPostStore)(nil)

// MemoryPostStore is an in-memory PostStore backed by a circular buffer.
// When the buffer is full, the oldest post is overwritten.
type MemoryPostStore struct {
	mu       sync.RWMutex
	posts    []*PostInfo
	capacity int
	head     int // next write position
	count    int // number of stored posts (up to capacity)
}

// NewMemoryPostStore creates an in-memory post store with the given capacity.
// If capacity is 0, DefaultMaxPosts is used.
func NewMemoryPostStore(capacity int) *MemoryPostStore {
	if capacity <= 0 {
		capacity = DefaultMaxPosts
	}
	return &MemoryPostStore{
		posts:    make([]*PostInfo, capacity),
		capacity: capacity,
	}
}

// AddPost adds a post to the circular buffer. When full, the oldest post
// is overwritten.
func (s *MemoryPostStore) AddPost(p *PostInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Copy the post to avoid aliasing
	stored := &PostInfo{
		Timestamp: p.Timestamp,
		SenderID:  p.SenderID,
	}
	if len(p.Content) > 0 {
		stored.Content = make([]byte, len(p.Content))
		copy(stored.Content, p.Content)
	}

	s.posts[s.head] = stored
	s.head = (s.head + 1) % s.capacity
	if s.count < s.capacity {
		s.count++
	}
	return nil
}

// GetPostsSince returns posts with Timestamp > timestamp, ordered oldest first.
func (s *MemoryPostStore) GetPostsSince(timestamp uint32) []*PostInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*PostInfo

	// Iterate from oldest to newest
	start := s.oldestIndex()
	for i := 0; i < s.count; i++ {
		idx := (start + i) % s.capacity
		p := s.posts[idx]
		if p != nil && p.Timestamp > timestamp {
			result = append(result, p)
		}
	}
	return result
}

// Count returns the number of stored posts.
func (s *MemoryPostStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.count
}

// Clear removes all posts.
func (s *MemoryPostStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.posts {
		s.posts[i] = nil
	}
	s.head = 0
	s.count = 0
}

// oldestIndex returns the index of the oldest post in the circular buffer.
// Must be called with s.mu held.
func (s *MemoryPostStore) oldestIndex() int {
	if s.count < s.capacity {
		return 0 // buffer not yet wrapped
	}
	return s.head // head points to the oldest entry after wrapping
}
