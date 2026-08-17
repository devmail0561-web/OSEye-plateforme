//go:build linux

// Package resilience_test contains end-to-end resilience tests for the agent
// pipeline: buffer durability, drain on server-down, and batcher shutdown flush.
package resilience_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	gen "github.com/devmail0561-web/OSEye-plateforme/agent/gen"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/buffer"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/chain"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/transport"
)

const bufSize = 1 << 20 // 1 MB in-memory connection

// ── helpers ──────────────────────────────────────────────────────────────────

// fakeServer is an AgentService that records accepted event counts.
type fakeServer struct {
	gen.UnimplementedAgentServiceServer
	mu       sync.Mutex
	received int
}

func (s *fakeServer) IngestEvents(stream gen.AgentService_IngestEventsServer) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			break
		}
		s.mu.Lock()
		s.received += len(req.GetEvents())
		s.mu.Unlock()
	}
	return stream.SendAndClose(&gen.IngestResponse{Accepted: 1})
}

func (s *fakeServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.received
}

// startServer starts a gRPC server over a bufconn listener and returns a
// function to stop it and the listener.
func startServer(t *testing.T) (*fakeServer, *bufconn.Listener, func()) {
	t.Helper()
	lis := bufconn.Listen(bufSize)
	srv := &fakeServer{}
	gs := grpc.NewServer()
	gen.RegisterAgentServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	return srv, lis, func() {
		gs.Stop()
		lis.Close()
	}
}

// dialBufconn connects to a bufconn listener with insecure credentials.
func dialBufconn(t *testing.T, lis *bufconn.Listener) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	return conn
}

// makeProtoPayload builds a minimal serialised UniversalEventPB.
func makeProtoPayload(t *testing.T, n int) []byte {
	t.Helper()
	pb := &gen.UniversalEventPB{
		TimestampNs: int64(n),
		Collector:   "procfs",
		Os:          "linux",
		HashChain:   make([]byte, 32),
	}
	b, err := proto.Marshal(pb)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	return b
}

// ── tests ─────────────────────────────────────────────────────────────────────

// TestBufferPersistsEventsWhenServerDown verifies that events pushed to the
// SQLite buffer while the server is unavailable are not lost, and that a
// subsequent drain delivers them.
func TestBufferPersistsEventsWhenServerDown(t *testing.T) {
	buf, err := buffer.Open(":memory:")
	if err != nil {
		t.Fatalf("buffer.Open: %v", err)
	}
	defer buf.Close()

	// Push 100 proto events while there is no server at all.
	var payloads [][]byte
	for i := range 100 {
		payloads = append(payloads, makeProtoPayload(t, i))
	}
	if err := buf.Push(payloads); err != nil {
		t.Fatalf("buf.Push: %v", err)
	}

	n, err := buf.Len()
	if err != nil {
		t.Fatalf("buf.Len: %v", err)
	}
	if n != 100 {
		t.Errorf("buffer len = %d, want 100", n)
	}

	// Now start a server and drain.
	srv, lis, stop := startServer(t)
	defer stop()

	conn := dialBufconn(t, lis)
	defer conn.Close()

	ch := chain.New()
	s := fakeSignerAlwaysOK{}
	client := transport.NewClientFromConn(conn, ch, s)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	drainBuf(ctx, t, client, buf)

	if srv.count() != 100 {
		t.Errorf("server received %d events, want 100", srv.count())
	}
	if n, _ := buf.Len(); n != 0 {
		t.Errorf("buffer still has %d events after drain, want 0", n)
	}
}

// TestDrainPreservesAllProtoFields verifies that proto.Unmarshal in drainBuffer
// reconstructs the event faithfully — no fields are lost in the SQLite round-trip.
func TestDrainPreservesAllProtoFields(t *testing.T) {
	buf, err := buffer.Open(":memory:")
	if err != nil {
		t.Fatalf("buffer.Open: %v", err)
	}
	defer buf.Close()

	original := &gen.UniversalEventPB{
		TimestampNs: 1_700_000_000_000_000_000,
		Hostname:    "test-host",
		Collector:   "procfs",
		Os:          "linux",
		Category:    "process",
		Type:        "snapshot",
		Severity:    "info",
		Pid:         1234,
		Ppid:        1,
		Uid:         1000,
		Gid:         1000,
		ProcessName: "bash",
		Executable:  "/bin/bash",
		Cmdline:     "bash -c ls",
		HashChain:   make([]byte, 32),
	}
	raw, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	if err := buf.Push([][]byte{raw}); err != nil {
		t.Fatalf("buf.Push: %v", err)
	}

	// Simulate the drain: Pop → Unmarshal.
	popped, err := buf.Pop(1)
	if err != nil || len(popped) != 1 {
		t.Fatalf("buf.Pop: err=%v len=%d", err, len(popped))
	}
	var reconstructed gen.UniversalEventPB
	if err := proto.Unmarshal(popped[0], &reconstructed); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}

	if !proto.Equal(original, &reconstructed) {
		t.Errorf("reconstructed event differs from original\ngot:  %v\nwant: %v", &reconstructed, original)
	}
}

// TestBatcherFlushesOnChannelClose verifies that the Batcher sends a partial
// batch (< batchSize) when the input channel is closed before the batch is full.
func TestBatcherFlushesOnChannelClose(t *testing.T) {
	srv, lis, stop := startServer(t)
	defer stop()

	conn := dialBufconn(t, lis)
	defer conn.Close()

	ch := chain.New()
	s := fakeSignerAlwaysOK{}
	client := transport.NewClientFromConn(conn, ch, s)

	// batchSize = 100, but we only send 50 events.
	batcher := transport.NewBatcher(100, 5*time.Second)
	eventCh := make(chan collector.RawEvent, 64)
	ctx := context.Background()

	done := make(chan struct{})
	var batcherErr error
	go func() {
		defer close(done)
		batcherErr = batcher.Run(ctx, eventCh, func(batch []collector.RawEvent) error {
			req := make([]*gen.UniversalEventPB, len(batch))
			for i, ev := range batch {
				req[i] = &gen.UniversalEventPB{
					TimestampNs: ev.Timestamp,
					Collector:   ev.Source,
					HashChain:   make([]byte, 32),
				}
			}
			sendCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			return client.SendBatch(sendCtx, req)
		})
	}()

	const n = 50
	for i := range n {
		eventCh <- collector.RawEvent{
			Source:    "procfs",
			OS:        "linux",
			Timestamp: int64(i),
			Raw:       []byte(`{}`),
		}
	}
	// Closing the channel signals the batcher to flush whatever it has.
	close(eventCh)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("batcher did not exit within 5s after channel close")
	}

	if batcherErr != nil {
		t.Errorf("batcher error: %v", batcherErr)
	}
	if srv.count() != n {
		t.Errorf("server received %d events, want %d", srv.count(), n)
	}
}

// TestBatcherFlushesOnContextCancel verifies that the Batcher flushes its
// current batch when the context is cancelled while events are pending.
func TestBatcherFlushesOnContextCancel(t *testing.T) {
	srv, lis, stop := startServer(t)
	defer stop()

	conn := dialBufconn(t, lis)
	defer conn.Close()

	ch := chain.New()
	s := fakeSignerAlwaysOK{}
	client := transport.NewClientFromConn(conn, ch, s)

	// batchSize = 200 so the batch never fills on its own.
	batcher := transport.NewBatcher(200, 10*time.Second)
	eventCh := make(chan collector.RawEvent, 64)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = batcher.Run(ctx, eventCh, func(batch []collector.RawEvent) error {
			req := make([]*gen.UniversalEventPB, len(batch))
			for i, ev := range batch {
				req[i] = &gen.UniversalEventPB{
					TimestampNs: ev.Timestamp,
					Collector:   ev.Source,
					HashChain:   make([]byte, 32),
				}
			}
			// Background context so the send survives context cancellation.
			sendCtx, sc := context.WithTimeout(context.Background(), 3*time.Second)
			defer sc()
			return client.SendBatch(sendCtx, req)
		})
	}()

	const n = 30
	// Feed events directly into the batcher's internal select loop.
	// Give the goroutine time to start and block on the select.
	time.Sleep(20 * time.Millisecond)
	for i := range n {
		eventCh <- collector.RawEvent{
			Source:    "procfs",
			OS:        "linux",
			Timestamp: int64(i),
			Raw:       []byte(`{}`),
		}
	}
	// Wait briefly to ensure the batcher has processed all n events from the
	// channel and they are sitting in its internal batch slice.
	time.Sleep(50 * time.Millisecond)

	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("batcher did not exit within 3s after context cancel")
	}

	// Allow the async gRPC call (launched inside the flush) to land.
	time.Sleep(100 * time.Millisecond)
	if srv.count() != n {
		t.Errorf("server received %d events, want %d", srv.count(), n)
	}
}

// ── stubs ─────────────────────────────────────────────────────────────────────

// fakeSignerAlwaysOK satisfies the signer interface used by transport.
type fakeSignerAlwaysOK struct{}

func (fakeSignerAlwaysOK) Sign([]byte) ([]byte, error) { return make([]byte, 64), nil }
func (fakeSignerAlwaysOK) PublicKey() []byte           { return make([]byte, 32) }

// drainBuf pops all buffered payloads and sends them via client.SendBatch.
// Mirrors the drainBuffer() logic in main.go for use in tests.
func drainBuf(ctx context.Context, t *testing.T, client transport.BatchSender, buf *buffer.Buffer) {
	t.Helper()
	for {
		payloads, err := buf.Pop(500)
		if err != nil || len(payloads) == 0 {
			return
		}
		var pbs []*gen.UniversalEventPB
		for _, p := range payloads {
			var pb gen.UniversalEventPB
			if err := proto.Unmarshal(p, &pb); err != nil {
				t.Logf("unmarshal failed: %v", err)
				continue
			}
			pbs = append(pbs, &pb)
		}
		if len(pbs) == 0 {
			continue
		}
		if err := client.SendBatch(ctx, pbs); err != nil {
			// Re-push on failure (mirrors main.go H11 fix).
			_ = buf.Push(payloads)
			t.Logf("SendBatch failed during drain: %v", err)
			return
		}
	}
}
