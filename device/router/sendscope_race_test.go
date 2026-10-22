package router

import (
	"sync"
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
)

// A companion app can change the send scope while the node is sending, so the
// scope must be safe to change concurrently (run with -race).
func TestSendScopeConcurrentChange(t *testing.T) {
	r := New(Config{SelfID: selfID(0xAA)})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 100 {
			r.SetSendScope(TransportKey{byte(i)})
		}
	}()
	go func() {
		defer wg.Done()
		for range 100 {
			r.SendFloodScoped(&codec.Packet{
				Header:  codec.PayloadTypeTxtMsg << codec.PHTypeShift,
				Payload: []byte{1, 2, 3},
			})
			_ = r.ResolveReplyScope(nil)
		}
	}()
	wg.Wait()
}
