package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	gen "github.com/oseye/agent/gen"
	"github.com/oseye/agent/internal/buffer"
	"github.com/oseye/agent/internal/chain"
	"github.com/oseye/agent/internal/collector"
	"github.com/oseye/agent/internal/config"
	"github.com/oseye/agent/internal/platform"
	_ "github.com/oseye/agent/internal/platform/linux" // register LinuxDriver via init()
	"github.com/oseye/agent/internal/signer"
	"github.com/oseye/agent/internal/transport"
)

const (
	fanInBufSize  = 512
	shutdownDrain = 5 * time.Second
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}

	// ── Platform resolution ──────────────────────────────────────────────────
	driver, err := platform.Resolve()
	if err != nil {
		log.Error("platform resolve failed", "err", err)
		os.Exit(1)
	}
	log.Info("platform detected", "name", driver.Name())

	collectors, err := driver.Collectors(cfg)
	if err != nil {
		log.Error("collectors init failed", "err", err)
		os.Exit(1)
	}

	// ── Crypto ───────────────────────────────────────────────────────────────
	ch := chain.New()
	var s *signer.Signer
	if cfg.TLSCertFile != "" {
		s, err = signer.New(cfg.TLSKeyFile)
		if err != nil {
			log.Warn("key file unavailable, using ephemeral signer", "err", err)
		}
	}
	if s == nil {
		s, err = signer.NewEphemeral()
		if err != nil {
			log.Error("ephemeral signer failed", "err", err)
			os.Exit(1)
		}
	}

	// ── Offline buffer ────────────────────────────────────────────────────────
	buf, err := buffer.Open(cfg.BufferPath)
	if err != nil {
		log.Error("buffer open failed", "err", err, "path", cfg.BufferPath)
		os.Exit(1)
	}
	defer buf.Close()

	// ── gRPC transport ────────────────────────────────────────────────────────
	client, err := transport.New(cfg, ch, s)
	if err != nil {
		log.Warn("grpc client init failed — running in buffer-only mode", "err", err)
		client = nil
	}
	if client != nil {
		defer client.Close()
	}

	// ── Context with SIGTERM/SIGINT ───────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Info("shutdown signal received — draining")
		cancel()
	}()

	// ── Collector manager ─────────────────────────────────────────────────────
	mgr := collector.NewManager(collectors, fanInBufSize)
	if err := mgr.Start(ctx); err != nil {
		log.Error("collector manager start failed", "err", err)
		os.Exit(1)
	}
	log.Info("collectors started", "count", len(collectors))

	// ── Batcher + send loop ───────────────────────────────────────────────────
	batcher := transport.NewBatcher(cfg.BatchSize, cfg.BatchTimeout)
	go func() {
		err := batcher.Run(ctx, mgr.Events(), func(batch []collector.RawEvent) error {
			return sendBatch(ctx, log, cfg, client, buf, ch, s, batch)
		})
		if err != nil && err != context.Canceled {
			log.Error("batcher exited with error", "err", err)
		}
	}()

	// ── Wait for shutdown + drain ─────────────────────────────────────────────
	<-ctx.Done()
	mgr.Stop()

	// Drain buffer: flush remaining buffered events to server with a deadline.
	if client != nil {
		drainCtx, drainCancel := context.WithTimeout(context.Background(), shutdownDrain)
		defer drainCancel()
		drainBuffer(drainCtx, log, client, buf)
	}

	log.Info("agent stopped")
}

// sendBatch serialises events, appends to offline buffer as fallback, and
// tries to send the batch immediately via gRPC. On transport failure, events
// are left in the buffer for the next drain cycle.
func sendBatch(
	ctx context.Context,
	log *slog.Logger,
	cfg *config.Config,
	client *transport.GRPCClient,
	buf *buffer.Buffer,
	ch *chain.Chain,
	s *signer.Signer,
	batch []collector.RawEvent,
) error {
	pbEvents := make([]*gen.UniversalEventPB, 0, len(batch))
	rawPayloads := make([][]byte, 0, len(batch))

	hostname, _ := os.Hostname()

	for _, ev := range batch {
		raw := ev.Raw
		if raw == nil {
			var err error
			raw, err = json.Marshal(ev)
			if err != nil {
				log.Warn("event marshal failed", "err", err)
				continue
			}
		}
		hashChain := ch.Append(raw)
		pb := &gen.UniversalEventPB{
			TimestampNs: ev.Timestamp,
			Hostname:    hostname,
			Collector:   ev.Source,
			Os:          ev.OS,
			HashChain:   hashChain,
		}
		pbEvents = append(pbEvents, pb)
		rawPayloads = append(rawPayloads, raw)
	}

	if len(pbEvents) == 0 {
		return nil
	}

	// Always buffer first — ensures no event loss on transport failure.
	if err := buf.Push(rawPayloads); err != nil {
		log.Warn("buffer push failed", "err", err)
	}

	if client == nil {
		return nil
	}

	sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := client.SendBatch(sendCtx, pbEvents); err != nil {
		log.Warn("send batch failed — events buffered", "err", err, "count", len(pbEvents))
		return nil // not fatal; buffer holds the events
	}

	// Sent successfully — dequeue from buffer.
	if _, err := buf.Pop(len(rawPayloads)); err != nil {
		log.Warn("buffer pop failed after successful send", "err", err)
	}

	return nil
}

// drainBuffer reads any buffered events and ships them before shutdown.
func drainBuffer(ctx context.Context, log *slog.Logger, client *transport.GRPCClient, buf *buffer.Buffer) {
	for {
		select {
		case <-ctx.Done():
			log.Warn("drain timeout — some buffered events may not have been sent")
			return
		default:
		}

		payloads, err := buf.Pop(500)
		if err != nil || len(payloads) == 0 {
			return
		}

		drainChain := chain.New()
		pbEvents := make([]*gen.UniversalEventPB, 0, len(payloads))
		for _, p := range payloads {
			hashChain := drainChain.Append(p)
			pbEvents = append(pbEvents, &gen.UniversalEventPB{
				HashChain: hashChain,
			})
		}

		if err := client.SendBatch(ctx, pbEvents); err != nil {
			log.Warn("drain send failed", "err", err)
			return
		}
		log.Info("drained buffered events", "count", len(payloads))
	}
}
