package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	gen "github.com/oseye/agent/gen"
	"github.com/oseye/agent/internal/buffer"
	"github.com/oseye/agent/internal/chain"
	"github.com/oseye/agent/internal/collector"
	"github.com/oseye/agent/internal/commands"
	"github.com/oseye/agent/internal/config"
	"github.com/oseye/agent/internal/enrollment"
	"github.com/oseye/agent/internal/mapper"
	"github.com/oseye/agent/internal/platform"
	_ "github.com/oseye/agent/internal/platform/linux" // register LinuxDriver via init()
	"github.com/oseye/agent/internal/policy"
	"github.com/oseye/agent/internal/responder"
	"github.com/oseye/agent/internal/signer"
	"github.com/oseye/agent/internal/transport"
	"github.com/oseye/agent/internal/watchdog"
)

const (
	fanInBufSize  = 512
	shutdownDrain = 5 * time.Second
)

func main() {
	// H2 fix: set as default so all packages (watchdog, policy, commands) use JSON logger.
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	cfg, err := config.Load()
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}

	// ── Agent identity ────────────────────────────────────────────────────────
	// L10 fix: log hostname resolution failure instead of silently ignoring it.
	hostname, err := os.Hostname()
	if err != nil {
		log.Warn("hostname unavailable, using empty string", "err", err)
		hostname = ""
	}

	// H1 fix: store agentID as 16-byte binary UUID, not as a 36-char ASCII string.
	var agentUUID uuid.UUID
	if cfg.AgentID != "" {
		agentUUID, err = uuid.Parse(cfg.AgentID)
		if err != nil {
			log.Warn("invalid OSEYE_AGENT_ID, generating ephemeral UUID", "err", err)
			agentUUID = uuid.New()
		}
	} else {
		agentUUID = uuid.New()
	}
	agentIDBytes := agentUUID[:]
	mp := mapper.New(hostname, agentIDBytes)

	// ── Auto-enrollment (first boot only) ────────────────────────────────────
	if err := enrollment.Enroll(enrollment.EnrollParams{
		TLSCertFile: cfg.TLSCertFile,
		TLSKeyFile:  cfg.TLSKeyFile,
		CACertFile:  cfg.CACertFile,
		EnrollURL:   cfg.EnrollServerURL,
		EnrollToken: cfg.EnrollToken,
		Hostname:    hostname,
	}); err != nil {
		log.Error("enrollment failed — continuing without cert", "err", err)
		// Non-fatal: agent runs in buffer-only mode if gRPC init fails later.
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
	// Use a dedicated Ed25519 signing key (OSEYE_ED25519_SIGNING_KEY), separate
	// from the mTLS key which may be RSA/ECDSA depending on the CA.
	ch := chain.New()
	var s *signer.Signer
	if cfg.Ed25519KeyFile != "" {
		s, err = signer.New(cfg.Ed25519KeyFile)
		if err != nil {
			log.Warn("ed25519 key file unavailable, using ephemeral signer", "err", err)
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
	// M5 fix: buf.Close() called explicitly on every exit path, not only via defer,
	// because os.Exit() skips deferred calls.
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
	// L11 fix: stop signal notification when the goroutine exits.
	go func() {
		defer signal.Stop(sigCh)
		<-sigCh
		log.Info("shutdown signal received — draining")
		cancel()
	}()

	// ── Collector manager ─────────────────────────────────────────────────────
	mgr := collector.NewManager(collectors, fanInBufSize)
	if err := mgr.Start(ctx); err != nil {
		log.Error("collector manager start failed", "err", err)
		buf.Close()
		os.Exit(1)
	}
	log.Info("collectors started", "count", len(collectors))

	// ── Resource watchdog ─────────────────────────────────────────────────────
	wd := watchdog.New(cfg.MaxCPUPct, float64(cfg.MaxMemMB), mgr)
	go wd.Run(ctx)

	// ── Response engine — state store + deduplicator ─────────────────────────
	stateStore, err := responder.OpenStateStore(cfg.BufferPath)
	if err != nil {
		log.Error("responder state store failed", "err", err)
		buf.Close()
		os.Exit(1)
	}
	defer stateStore.Close()
	dedup := responder.NewDeduplicator(60 * time.Second)

	// ── Policy + command streams ──────────────────────────────────────────────
	if client != nil {
		profileHandler := policy.NewHandler(mgr)
		policyClient := policy.NewClient(client.ServiceClient(), agentIDBytes, profileHandler.Apply)

		reporter := responder.NewReporter(client.ServiceClient(), 256)
		cmdClient := commands.NewClient(
			client.ServiceClient(), agentIDBytes, mgr,
			stateStore, dedup, reporter, cfg.QuarantineDir,
		)
		go policyClient.Run(ctx)
		go cmdClient.Run(ctx)
		go reporter.Run(ctx)
	}

	// ── Batcher + send loop ───────────────────────────────────────────────────
	batcher := transport.NewBatcher(cfg.BatchSize, cfg.BatchTimeout)
	var batcherWg sync.WaitGroup
	batcherWg.Add(1)
	go func() {
		defer batcherWg.Done()
		err := batcher.Run(ctx, mgr.Events(), func(batch []collector.RawEvent) error {
			return sendBatch(ctx, log, client, buf, ch, mp, batch)
		})
		if err != nil && err != context.Canceled {
			log.Error("batcher exited with error", "err", err)
		}
	}()

	// ── Wait for shutdown + drain ─────────────────────────────────────────────
	<-ctx.Done()
	mgr.Stop()
	// Wait for the batcher goroutine to finish before touching buf, preventing
	// a SQLite write-after-close race at shutdown (GO-004).
	batcherWg.Wait()

	// Drain buffer: flush remaining buffered events to server with a deadline.
	if client != nil {
		drainCtx, drainCancel := context.WithTimeout(context.Background(), shutdownDrain)
		defer drainCancel()
		drainBuffer(drainCtx, log, client, buf)
	}

	log.Info("agent stopped")
}

// sendBatch serialises events, writes to offline buffer as durability layer, and
// tries to send immediately via gRPC. On transport failure events stay buffered.
func sendBatch(
	ctx context.Context,
	log *slog.Logger,
	client *transport.GRPCClient,
	buf *buffer.Buffer,
	ch *chain.Chain,
	mp *mapper.EventMapper,
	batch []collector.RawEvent,
) error {
	pbEvents := make([]*gen.UniversalEventPB, 0, len(batch))
	protoPayloads := make([][]byte, 0, len(batch))

	for _, ev := range batch {
		if ev.Raw == nil {
			log.Warn("event has no raw payload, skipping", "source", ev.Source)
			continue
		}
		hashChain := ch.Append(ev.Raw)
		pb, err := mp.Map(ev, hashChain)
		if err != nil {
			log.Warn("event mapping failed, skipping", "err", err, "source", ev.Source)
			continue
		}
		protoBytes, err := proto.Marshal(pb)
		if err != nil {
			log.Warn("proto marshal failed, skipping", "err", err, "source", ev.Source)
			continue
		}
		pbEvents = append(pbEvents, pb)
		protoPayloads = append(protoPayloads, protoBytes)
	}

	if len(pbEvents) == 0 {
		return nil
	}

	// Always buffer first — ensures no event loss on transport failure.
	if err := buf.Push(protoPayloads); err != nil {
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
	if _, err := buf.Pop(len(protoPayloads)); err != nil {
		log.Warn("buffer pop failed after successful send", "err", err)
	}

	return nil
}

// drainBuffer reads buffered events and ships them before shutdown.
// H11 fix: on send failure, payloads are re-pushed to the buffer instead of dropped.
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

		pbEvents := make([]*gen.UniversalEventPB, 0, len(payloads))
		for _, p := range payloads {
			var pb gen.UniversalEventPB
			if err := proto.Unmarshal(p, &pb); err != nil {
				log.Warn("proto unmarshal failed during drain, skipping", "err", err)
				continue
			}
			pbEvents = append(pbEvents, &pb)
		}

		if len(pbEvents) == 0 {
			continue
		}

		if err := client.SendBatch(ctx, pbEvents); err != nil {
			log.Warn("drain send failed — re-buffering events", "err", err, "count", len(payloads))
			// Best-effort re-push so events survive a temporary send failure.
			if pushErr := buf.Push(payloads); pushErr != nil {
				log.Warn("re-buffer failed — events lost", "err", pushErr)
			}
			return
		}
		log.Info("drained buffered events", "count", len(pbEvents))
	}
}
