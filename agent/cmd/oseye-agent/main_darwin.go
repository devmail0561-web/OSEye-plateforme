//go:build darwin

// Package main — cross-platform agent entry point for Windows and macOS.
// On Linux the full agent (with autonomy, watchdog, responder, policy) is used;
// this minimal version covers collection + gRPC transport only.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	gen "github.com/oseye/agent/gen"
	"github.com/oseye/agent/internal/buffer"
	"github.com/oseye/agent/internal/chain"
	"github.com/oseye/agent/internal/collector"
	"github.com/oseye/agent/internal/config"
	"github.com/oseye/agent/internal/enrollment"
	"github.com/oseye/agent/internal/mapper"
	"github.com/oseye/agent/internal/platform"
	"github.com/oseye/agent/internal/signer"
	"github.com/oseye/agent/internal/transport"
)

var version = "dev"

const (
	fanInBufSize  = 512
	shutdownDrain = 5 * time.Second
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("oseye-agent %s\n", version)
		os.Exit(0)
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	log.Info("starting oseye-agent", "version", version)

	cfg, err := config.Load()
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	var agentUUID uuid.UUID
	if cfg.AgentID != "" {
		agentUUID, _ = uuid.Parse(cfg.AgentID)
	}
	if agentUUID == (uuid.UUID{}) {
		agentUUID = uuid.New()
	}
	agentIDBytes := agentUUID[:]

	// Auto-enroll if token is set and certs are missing
	if cfg.EnrollToken != "" {
		if err := enrollment.Enroll(enrollment.EnrollParams{
			TLSCertFile: cfg.TLSCertFile,
			TLSKeyFile:  cfg.TLSKeyFile,
			CACertFile:  cfg.CACertFile,
			EnrollURL:   cfg.EnrollServerURL,
			EnrollToken: cfg.EnrollToken,
			Hostname:    hostname,
		}); err != nil {
			log.Warn("auto-enrollment failed", "err", err)
		}
	}

	s, err := signer.New(cfg.Ed25519KeyFile)
	if err != nil {
		log.Warn("signer init failed — batches will be unsigned", "err", err)
		s, _ = signer.NewEphemeral()
	}

	ch := chain.New()

	buf, err := buffer.Open(cfg.BufferPath)
	if err != nil {
		log.Error("buffer open failed", "err", err, "path", cfg.BufferPath)
		os.Exit(1)
	}
	defer buf.Close()

	client, err := transport.New(cfg, ch, s)
	if err != nil {
		log.Warn("grpc client init failed — buffer-only mode", "err", err)
		client = nil
	}
	if client != nil {
		defer client.Close()
	}

	// Resolve platform driver and instantiate collectors
	driver, err := platform.Resolve()
	if err != nil {
		log.Error("platform driver not found", "err", err)
		os.Exit(1)
	}
	log.Info("platform driver loaded", "name", driver.Name())

	colls, err := driver.Collectors(cfg)
	if err != nil {
		log.Error("collectors init failed", "err", err)
		os.Exit(1)
	}

	mp := mapper.New(hostname, agentIDBytes)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fanIn := make(chan collector.RawEvent, fanInBufSize)

	// Start all collectors
	for _, c := range colls {
		if err := c.Start(ctx, fanIn); err != nil {
			log.Warn("collector start failed", "name", c.Name(), "err", err)
		} else {
			log.Info("collector started", "name", c.Name())
		}
	}

	// Event processing goroutine
	batchTimeout := cfg.BatchTimeout
	if batchTimeout == 0 {
		batchTimeout = time.Second
	}

	go func() {
		batch := make([]*gen.UniversalEventPB, 0, cfg.BatchSize)
		ticker := time.NewTicker(batchTimeout)
		defer ticker.Stop()

		flush := func() {
			if len(batch) == 0 {
				return
			}
			if err := sendBatchOther(ctx, log, client, buf, ch, mp, batch); err != nil {
				log.Debug("send batch error", "err", err)
			}
			batch = batch[:0]
		}

		for {
			select {
			case <-ctx.Done():
				flush()
				return
			case raw, ok := <-fanIn:
				if !ok {
					flush()
					return
				}
				ev, err := mp.Map(raw, ch.Current())
				if err != nil {
					log.Debug("map error", "source", raw.Source, "err", err)
					continue
				}
				batch = append(batch, ev)
				if len(batch) >= cfg.BatchSize {
					flush()
				}
			case <-ticker.C:
				flush()
			}
		}
	}()

	log.Info("agent running — waiting for signal")
	<-sigCh
	log.Info("shutdown signal received — stopping collectors")
	cancel()

	for _, c := range colls {
		c.Stop() //nolint:errcheck
	}

	if client != nil {
		drainCtx, drainCancel := context.WithTimeout(context.Background(), shutdownDrain)
		defer drainCancel()
		drainBufferOther(drainCtx, log, client, buf, ch, mp)
	}

	log.Info("agent stopped")
}

func sendBatchOther(
	ctx context.Context,
	log *slog.Logger,
	client *transport.GRPCClient,
	buf *buffer.Buffer,
	ch *chain.Chain,
	mp *mapper.EventMapper,
	events []*gen.UniversalEventPB,
) error {
	payloads := make([][]byte, 0, len(events))
	for _, ev := range events {
		b, err := proto.Marshal(ev)
		if err != nil {
			continue
		}
		payloads = append(payloads, b)
		_ = ch.Append(ev.ExtraJson)
	}

	if err := buf.Push(payloads); err != nil {
		log.Warn("buffer push failed", "err", err)
	}

	if client == nil {
		return nil
	}

	sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := client.SendBatch(sendCtx, events); err != nil {
		return err
	}

	if _, err := buf.Pop(len(payloads)); err != nil {
		log.Warn("buffer pop failed after send", "err", err)
	}
	return nil
}

func drainBufferOther(ctx context.Context, log *slog.Logger, client *transport.GRPCClient, buf *buffer.Buffer, ch *chain.Chain, mp *mapper.EventMapper) {
	var lastAckID int64
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		entries, err := buf.Replay(lastAckID, 500)
		if err != nil || len(entries) == 0 {
			return
		}
		pbEvents := make([]*gen.UniversalEventPB, 0, len(entries))
		for _, e := range entries {
			var pb gen.UniversalEventPB
			if err := proto.Unmarshal(e.Payload, &pb); err != nil {
				continue
			}
			pbEvents = append(pbEvents, &pb)
		}
		if len(pbEvents) == 0 {
			if err := buf.AckUntil(entries[len(entries)-1].ID); err == nil {
				lastAckID = entries[len(entries)-1].ID
			}
			continue
		}
		if err := client.SendBatch(ctx, pbEvents); err != nil {
			log.Warn("drain send failed", "err", err)
			return
		}
		maxID := entries[len(entries)-1].ID
		if err := buf.AckUntil(maxID); err != nil {
			log.Warn("drain ack failed", "err", err)
		}
		lastAckID = maxID
	}
}
