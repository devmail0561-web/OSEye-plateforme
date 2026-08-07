package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/zeebo/blake3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	gen "github.com/oseye/agent/gen"
	"github.com/oseye/agent/internal/chain"
	"github.com/oseye/agent/internal/config"
)

const (
	sendTimeout    = 10 * time.Second
	backoffInitial = 1 * time.Second
	backoffMax     = 30 * time.Second
	maxRetries     = 15
)

// Signer is the signing interface used by GRPCClient. *signer.Signer satisfies
// it, as does any test stub that provides Sign and PublicKey.
type Signer interface {
	Sign(data []byte) ([]byte, error)
	PublicKey() []byte
}

// GRPCClient wraps a gRPC connection to the OSEye server and exposes
// batch-sending with mTLS and Ed25519 batch signatures.
type GRPCClient struct {
	conn   *grpc.ClientConn
	client gen.AgentServiceClient
	chain  *chain.Chain
	signer Signer
}

// New creates a gRPC client with mTLS credentials loaded from cfg.
// It does NOT dial immediately — the connection is established lazily.
func New(cfg *config.Config, ch *chain.Chain, s Signer) (*GRPCClient, error) {
	tlsCreds, err := buildTLSCredentials(cfg)
	if err != nil {
		return nil, fmt.Errorf("transport: build TLS credentials: %w", err)
	}

	conn, err := grpc.NewClient(
		cfg.GRPCAddr,
		grpc.WithTransportCredentials(tlsCreds),
	)
	if err != nil {
		return nil, fmt.Errorf("transport: grpc dial %s: %w", cfg.GRPCAddr, err)
	}

	return &GRPCClient{
		conn:   conn,
		client: gen.NewAgentServiceClient(conn),
		chain:  ch,
		signer: s,
	}, nil
}

// SendBatch encodes the events into an IngestRequest, computes the batch
// signature, and transmits the request to the server via client-streaming RPC.
// On transient failure it retries with exponential backoff (max 30s per delay).
// Each send attempt has an individual timeout of 10s.
func (c *GRPCClient) SendBatch(ctx context.Context, events []*gen.UniversalEventPB) error {
	sig, err := batchSignature(c.chain, c.signer, events)
	if err != nil {
		return fmt.Errorf("transport: batch signature: %w", err)
	}

	req := &gen.IngestRequest{
		Events:         events,
		BatchSignature: sig,
	}

	delay := backoffInitial
	for attempt := 1; ; attempt++ {
		if attempt > maxRetries {
			return fmt.Errorf("max retries exceeded: %d attempts", maxRetries)
		}

		sendCtx, cancel := context.WithTimeout(ctx, sendTimeout)
		err := c.sendOnce(sendCtx, req)
		cancel()

		if err == nil {
			return nil
		}

		// Check if parent context is done.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Exponential backoff with cap.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
		if delay > backoffMax {
			delay = backoffMax
		}
	}
}

// sendOnce performs a single client-streaming RPC attempt.
func (c *GRPCClient) sendOnce(ctx context.Context, req *gen.IngestRequest) error {
	stream, err := c.client.IngestEvents(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}

	if err := stream.Send(req); err != nil {
		return fmt.Errorf("send: %w", err)
	}

	if _, err := stream.CloseAndRecv(); err != nil {
		return fmt.Errorf("close/recv: %w", err)
	}

	return nil
}

// ServiceClient returns the underlying AgentServiceClient for streaming RPCs
// (ReceivePolicy, StreamCommands).
func (c *GRPCClient) ServiceClient() gen.AgentServiceClient { return c.client }

// BatchSender is the minimal interface used by drainBuffer and resilience tests.
type BatchSender interface {
	SendBatch(ctx context.Context, events []*gen.UniversalEventPB) error
}

// NewClientFromConn creates a GRPCClient from an already-dialled connection.
// Intended for tests that use bufconn or similar in-memory transports.
func NewClientFromConn(conn *grpc.ClientConn, ch *chain.Chain, s Signer) *GRPCClient {
	return &GRPCClient{
		conn:   conn,
		client: gen.NewAgentServiceClient(conn),
		chain:  ch,
		signer: s,
	}
}

// Close tears down the underlying gRPC connection.
func (c *GRPCClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// batchSignature computes BLAKE3(hash_chain[0] || ... || hash_chain[N-1])
// over the hash_chain field of each event, then signs that digest with Ed25519.
func batchSignature(ch *chain.Chain, s Signer, events []*gen.UniversalEventPB) ([]byte, error) {
	h := blake3.New()
	for _, ev := range events {
		_, _ = h.Write(ev.GetHashChain())
	}
	var digest [32]byte
	h.Sum(digest[:0])

	sig, err := s.Sign(digest[:])
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// buildTLSCredentials loads the mTLS certificate pair and the CA pool from
// the paths stored in cfg. Returns a grpc/credentials.TransportCredentials.
func buildTLSCredentials(cfg *config.Config) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert/key: %w", err)
	}

	caPool := x509.NewCertPool()
	caPEM, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA cert: no valid PEM block found")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}

	return credentials.NewTLS(tlsCfg), nil
}
