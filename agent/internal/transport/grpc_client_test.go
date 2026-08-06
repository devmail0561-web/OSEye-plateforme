package transport

import (
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/zeebo/blake3"
	gen "github.com/oseye/agent/gen"
	"github.com/oseye/agent/internal/chain"
	"github.com/oseye/agent/internal/config"
	"github.com/oseye/agent/internal/signer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// ── batch signature tests ──────────────────────────────────────────────────

func TestBatchSignatureEmptyBatch(t *testing.T) {
	t.Parallel()
	ch := chain.New()
	s, err := signer.NewEphemeral()
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}
	sig, err := batchSignature(ch, s, nil)
	if err != nil {
		t.Fatalf("batchSignature: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("expected %d-byte signature, got %d", ed25519.SignatureSize, len(sig))
	}
}

func TestBatchSignatureCorrectness(t *testing.T) {
	t.Parallel()
	ch := chain.New()
	s, err := signer.NewEphemeral()
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}
	events := []*gen.UniversalEventPB{
		{HashChain: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")},
		{HashChain: []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")},
		{HashChain: []byte("cccccccccccccccccccccccccccccccc")},
	}
	h := blake3.New()
	for _, ev := range events {
		h.Write(ev.GetHashChain())
	}
	var expected [32]byte
	h.Sum(expected[:0])

	sig, err := batchSignature(ch, s, events)
	if err != nil {
		t.Fatalf("batchSignature: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("expected %d-byte signature, got %d", ed25519.SignatureSize, len(sig))
	}
	pubKey := ed25519.PublicKey(s.PublicKey())
	if !ed25519.Verify(pubKey, expected[:], sig) {
		t.Fatal("signature verification failed")
	}
}

func TestBatchSignatureDifferentEvents(t *testing.T) {
	t.Parallel()
	ch := chain.New()
	s, _ := signer.NewEphemeral()
	sigA, _ := batchSignature(ch, s, []*gen.UniversalEventPB{{HashChain: []byte("aaa")}})
	sigB, _ := batchSignature(ch, s, []*gen.UniversalEventPB{{HashChain: []byte("bbb")}})
	if string(sigA) == string(sigB) {
		t.Fatal("expected different signatures for different event sets")
	}
}

func TestNewClientMissingCerts(t *testing.T) {
	t.Parallel()
	ch := chain.New()
	s, _ := signer.NewEphemeral()
	cfg := &config.Config{
		GRPCAddr:    "localhost:9999",
		TLSCertFile: "/nonexistent/cert.pem",
		TLSKeyFile:  "/nonexistent/key.pem",
		CACertFile:  "/nonexistent/ca.pem",
	}
	_, err := New(cfg, ch, s)
	if err == nil {
		t.Fatal("expected error with missing certs")
	}
}

// ── bufconn server helpers ─────────────────────────────────────────────────

const bufSize = 1 << 20

// fakeAgentServer is a minimal AgentServiceServer that records received batches.
type fakeAgentServer struct {
	gen.UnimplementedAgentServiceServer
	received []*gen.IngestRequest
}

func (f *fakeAgentServer) IngestEvents(
	stream gen.AgentService_IngestEventsServer,
) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	f.received = append(f.received, req)
	return stream.SendAndClose(&gen.IngestResponse{Accepted: int32(len(req.Events))})
}

func newBufconnClient(t *testing.T, srv *grpc.Server) (*GRPCClient, func()) {
	t.Helper()
	lis := bufconn.Listen(bufSize)

	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
	)
	if err != nil {
		t.Fatalf("bufconn dial: %v", err)
	}

	ch := chain.New()
	s, _ := signer.NewEphemeral()
	client := &GRPCClient{
		conn:   conn,
		client: gen.NewAgentServiceClient(conn),
		chain:  ch,
		signer: s,
	}
	cleanup := func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	}
	return client, cleanup
}

// ── SendBatch tests ────────────────────────────────────────────────────────

func TestSendBatch_Success(t *testing.T) {
	fake := &fakeAgentServer{}
	srv := grpc.NewServer()
	gen.RegisterAgentServiceServer(srv, fake)

	client, cleanup := newBufconnClient(t, srv)
	defer cleanup()

	events := []*gen.UniversalEventPB{
		{HashChain: make([]byte, 32), Hostname: "host1"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.SendBatch(ctx, events); err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
	if len(fake.received) != 1 {
		t.Fatalf("server received %d batches, want 1", len(fake.received))
	}
}

func TestSendBatch_ServerError_RetriesAndContextCancelled(t *testing.T) {
	// A server that always returns an error.
	errServer := &alwaysErrServer{}
	srv := grpc.NewServer()
	gen.RegisterAgentServiceServer(srv, errServer)

	client, cleanup := newBufconnClient(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	err := client.SendBatch(ctx, []*gen.UniversalEventPB{{HashChain: make([]byte, 32)}})
	if err == nil {
		t.Fatal("expected error from always-failing server")
	}
}

type alwaysErrServer struct {
	gen.UnimplementedAgentServiceServer
}

func (a *alwaysErrServer) IngestEvents(stream gen.AgentService_IngestEventsServer) error {
	return status.Error(codes.Unavailable, "forced error")
}

// ── Close test ─────────────────────────────────────────────────────────────

func TestClose(t *testing.T) {
	fake := &fakeAgentServer{}
	srv := grpc.NewServer()
	gen.RegisterAgentServiceServer(srv, fake)

	client, cleanup := newBufconnClient(t, srv)
	defer cleanup()

	if err := client.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Second Close should not panic.
	_ = client.Close()
}
