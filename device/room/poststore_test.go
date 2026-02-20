package room

import (
	"testing"

	"github.com/kabili207/meshcore-go/core"
)

func makePost(ts uint32, sender byte, content string) *PostInfo {
	return &PostInfo{
		Timestamp: ts,
		SenderID:  core.MeshCoreID{sender},
		Content:   []byte(content),
	}
}

func TestMemoryPostStore_AddPost(t *testing.T) {
	s := NewMemoryPostStore(10)

	if err := s.AddPost(makePost(100, 0x01, "hello")); err != nil {
		t.Fatalf("AddPost failed: %v", err)
	}
	if s.Count() != 1 {
		t.Errorf("Count() = %d, want 1", s.Count())
	}
}

func TestMemoryPostStore_AddPost_CopiesContent(t *testing.T) {
	s := NewMemoryPostStore(10)

	content := []byte("hello")
	s.AddPost(&PostInfo{Timestamp: 100, Content: content})

	// Mutate original — should not affect stored post
	content[0] = 'X'

	posts := s.GetPostsSince(0)
	if len(posts) != 1 {
		t.Fatal("expected 1 post")
	}
	if string(posts[0].Content) != "hello" {
		t.Errorf("content = %q, want %q (should be a copy)", string(posts[0].Content), "hello")
	}
}

func TestMemoryPostStore_GetPostsSince(t *testing.T) {
	s := NewMemoryPostStore(10)

	s.AddPost(makePost(100, 0x01, "a"))
	s.AddPost(makePost(200, 0x02, "b"))
	s.AddPost(makePost(300, 0x03, "c"))

	// All posts since 0
	posts := s.GetPostsSince(0)
	if len(posts) != 3 {
		t.Fatalf("GetPostsSince(0) = %d posts, want 3", len(posts))
	}

	// Posts since 100 (exclusive)
	posts = s.GetPostsSince(100)
	if len(posts) != 2 {
		t.Fatalf("GetPostsSince(100) = %d posts, want 2", len(posts))
	}
	if posts[0].Timestamp != 200 {
		t.Errorf("first post timestamp = %d, want 200", posts[0].Timestamp)
	}
	if posts[1].Timestamp != 300 {
		t.Errorf("second post timestamp = %d, want 300", posts[1].Timestamp)
	}

	// Posts since 300 (nothing newer)
	posts = s.GetPostsSince(300)
	if len(posts) != 0 {
		t.Fatalf("GetPostsSince(300) = %d posts, want 0", len(posts))
	}
}

func TestMemoryPostStore_GetPostsSince_Order(t *testing.T) {
	s := NewMemoryPostStore(10)

	// Add in order
	for i := uint32(1); i <= 5; i++ {
		s.AddPost(makePost(i*100, 0x01, "msg"))
	}

	posts := s.GetPostsSince(0)
	if len(posts) != 5 {
		t.Fatalf("got %d posts, want 5", len(posts))
	}

	// Verify oldest-first ordering
	for i := 1; i < len(posts); i++ {
		if posts[i].Timestamp <= posts[i-1].Timestamp {
			t.Errorf("posts not in ascending order: [%d]=%d, [%d]=%d",
				i-1, posts[i-1].Timestamp, i, posts[i].Timestamp)
		}
	}
}

func TestMemoryPostStore_CircularBuffer(t *testing.T) {
	s := NewMemoryPostStore(3) // capacity 3

	s.AddPost(makePost(100, 0x01, "a"))
	s.AddPost(makePost(200, 0x02, "b"))
	s.AddPost(makePost(300, 0x03, "c"))

	if s.Count() != 3 {
		t.Errorf("Count() = %d, want 3", s.Count())
	}

	// Add one more — should overwrite oldest (100)
	s.AddPost(makePost(400, 0x04, "d"))

	if s.Count() != 3 {
		t.Errorf("Count() after wrap = %d, want 3", s.Count())
	}

	posts := s.GetPostsSince(0)
	if len(posts) != 3 {
		t.Fatalf("got %d posts, want 3", len(posts))
	}

	// Should have 200, 300, 400 (100 was evicted)
	if posts[0].Timestamp != 200 {
		t.Errorf("oldest post = %d, want 200 (100 should be evicted)", posts[0].Timestamp)
	}
	if posts[1].Timestamp != 300 {
		t.Errorf("middle post = %d, want 300", posts[1].Timestamp)
	}
	if posts[2].Timestamp != 400 {
		t.Errorf("newest post = %d, want 400", posts[2].Timestamp)
	}
}

func TestMemoryPostStore_CircularBuffer_MultipleWraps(t *testing.T) {
	s := NewMemoryPostStore(3)

	// Write 7 posts into capacity-3 buffer (wraps twice + 1)
	for i := uint32(1); i <= 7; i++ {
		s.AddPost(makePost(i*100, 0x01, "msg"))
	}

	if s.Count() != 3 {
		t.Errorf("Count() = %d, want 3", s.Count())
	}

	posts := s.GetPostsSince(0)
	if len(posts) != 3 {
		t.Fatalf("got %d posts, want 3", len(posts))
	}

	// Should have 500, 600, 700
	if posts[0].Timestamp != 500 {
		t.Errorf("oldest = %d, want 500", posts[0].Timestamp)
	}
	if posts[2].Timestamp != 700 {
		t.Errorf("newest = %d, want 700", posts[2].Timestamp)
	}
}

func TestMemoryPostStore_GetPostsSince_AfterWrap(t *testing.T) {
	s := NewMemoryPostStore(3)

	s.AddPost(makePost(100, 0x01, "a"))
	s.AddPost(makePost(200, 0x02, "b"))
	s.AddPost(makePost(300, 0x03, "c"))
	s.AddPost(makePost(400, 0x04, "d")) // evicts 100

	// Get posts since 250 → should return 300 and 400
	posts := s.GetPostsSince(250)
	if len(posts) != 2 {
		t.Fatalf("GetPostsSince(250) = %d posts, want 2", len(posts))
	}
	if posts[0].Timestamp != 300 {
		t.Errorf("first = %d, want 300", posts[0].Timestamp)
	}
	if posts[1].Timestamp != 400 {
		t.Errorf("second = %d, want 400", posts[1].Timestamp)
	}
}

func TestMemoryPostStore_Clear(t *testing.T) {
	s := NewMemoryPostStore(10)

	s.AddPost(makePost(100, 0x01, "a"))
	s.AddPost(makePost(200, 0x02, "b"))

	s.Clear()

	if s.Count() != 0 {
		t.Errorf("Count() after clear = %d, want 0", s.Count())
	}
	posts := s.GetPostsSince(0)
	if len(posts) != 0 {
		t.Errorf("GetPostsSince(0) after clear = %d posts, want 0", len(posts))
	}
}

func TestMemoryPostStore_Clear_ThenAdd(t *testing.T) {
	s := NewMemoryPostStore(3)

	s.AddPost(makePost(100, 0x01, "a"))
	s.AddPost(makePost(200, 0x02, "b"))
	s.Clear()

	s.AddPost(makePost(300, 0x03, "c"))

	if s.Count() != 1 {
		t.Errorf("Count() = %d, want 1", s.Count())
	}
	posts := s.GetPostsSince(0)
	if len(posts) != 1 {
		t.Fatalf("got %d posts, want 1", len(posts))
	}
	if posts[0].Timestamp != 300 {
		t.Errorf("timestamp = %d, want 300", posts[0].Timestamp)
	}
}

func TestMemoryPostStore_DefaultCapacity(t *testing.T) {
	s := NewMemoryPostStore(0)
	if s.capacity != DefaultMaxPosts {
		t.Errorf("capacity = %d, want %d", s.capacity, DefaultMaxPosts)
	}
}

func TestMemoryPostStore_EmptyStore(t *testing.T) {
	s := NewMemoryPostStore(10)

	if s.Count() != 0 {
		t.Errorf("Count() = %d, want 0", s.Count())
	}
	posts := s.GetPostsSince(0)
	if len(posts) != 0 {
		t.Errorf("GetPostsSince(0) = %d posts, want 0", len(posts))
	}
}

func TestMemoryPostStore_SingleCapacity(t *testing.T) {
	s := NewMemoryPostStore(1)

	s.AddPost(makePost(100, 0x01, "a"))
	if s.Count() != 1 {
		t.Errorf("Count() = %d, want 1", s.Count())
	}

	s.AddPost(makePost(200, 0x02, "b"))
	if s.Count() != 1 {
		t.Errorf("Count() after wrap = %d, want 1", s.Count())
	}

	posts := s.GetPostsSince(0)
	if len(posts) != 1 {
		t.Fatalf("got %d posts, want 1", len(posts))
	}
	if posts[0].Timestamp != 200 {
		t.Errorf("timestamp = %d, want 200", posts[0].Timestamp)
	}
}
