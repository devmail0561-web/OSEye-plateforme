//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	gen "github.com/devmail0561-web/OSEye-plateforme/agent/gen"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/autonomy"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/buffer"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/chain"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/commands"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/config"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/enrollment"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/hostprofile"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/localrules"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/mapper"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/platform"
	// Platform driver is registered via platform_<os>.go in this package.
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/merger"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/policy"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/responder"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/signer"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/transport"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/watchdog"
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

	// H2 fix: set as default so all packages (watchdog, policy, commands) use JSON logger.
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	log.Info("starting oseye-agent", "version", version)

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
	log.Info("agent_identity", "uuid", agentUUID.String(), "hostname", hostname)
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

	// ── Autonomous local rule engine ─────────────────────────────────────────
	dataDir := getenv("OSEYE_DATA_DIR", "/var/lib/oseye")

	profileStore, err := hostprofile.NewProfileStore(dataDir)
	if err != nil {
		log.Error("host profile store failed", "err", err)
		// CORE-005: stateStore was initialised earlier; close it before exit so its
		// underlying storage is flushed (os.Exit skips deferred calls).
		stateStore.Close()
		buf.Close()
		os.Exit(1)
	}

	ruleStore, err := localrules.NewStore(dataDir, nil)
	if err != nil {
		log.Error("local rule store failed", "err", err)
		// CORE-005: same stateStore.Close() guard.
		stateStore.Close()
		buf.Close()
		os.Exit(1)
	}

	profile := profileStore.Current()
	engineCfg := localrules.EngineConfig{
		MaxRules:             profile.Budget.MaxRules,
		BudgetPerEventMicros: profile.Budget.BudgetPerEventMicros,
		MaxCorrelationGroups: profile.Budget.MaxCorrelationGroups,
		MaxCorrelationEvents: profile.Budget.MaxCorrelationEvents,
		RegexCacheSize:       256,
	}
	if engineCfg.MaxRules == 0 {
		engineCfg = localrules.DefaultEngineConfig()
	}
	ruleEngine := localrules.NewEngine(ruleStore, engineCfg)
	ruleEngine.SetProfileRefs(profile.BaselineRefs())

	killSwitch := autonomy.NewKillSwitch()

	var autoReporter *responder.Reporter
	var autoController *autonomy.Controller

	// ── Policy + command streams ──────────────────────────────────────────────
	if client != nil {
		profileHandler := policy.NewHandler(mgr)

		// Wrap profile handler to also update local profile store, rules, and engine.
		onProfile := func(p *gen.SurveillanceProfilePB) {
			profileHandler.Apply(p)
			if configJSON := p.GetConfigJson(); len(configJSON) > 0 {
				// Parse the config to check for embedded rule_set updates.
				var envelope struct {
					RuleSet json.RawMessage `json:"rule_set,omitempty"`
				}
				if err := json.Unmarshal(configJSON, &envelope); err == nil && len(envelope.RuleSet) > 0 {
					if err := ruleStore.Update(envelope.RuleSet); err != nil {
						slog.Default().Warn("rule update from policy failed", "err", err)
					} else {
						ruleEngine.Reload()
					}
				}

				_ = profileStore.Update(configJSON)
				updated := profileStore.Current()
				ruleEngine.SetProfileRefs(updated.BaselineRefs())
			}
		}

		policyClient := policy.NewClient(client.ServiceClient(), agentIDBytes, onProfile)

		autoReporter = responder.NewReporter(client.ServiceClient(), 256)
		cmdClient := commands.NewClient(
			client.ServiceClient(), agentIDBytes, mgr,
			stateStore, dedup, autoReporter, cfg.QuarantineDir, killSwitch,
		).WithConfig(cfg)
		go policyClient.Run(ctx)
		go cmdClient.Run(ctx)
		go autoReporter.Run(ctx)
	}

	// ── Autonomy controller ──────────────────────────────────────────────────
	autoCfg := autonomy.DefaultControllerConfig()
	autoCfg.QuarantineDir = cfg.QuarantineDir
	autoController = autonomy.NewController(
		ruleEngine, ruleStore, profileStore,
		stateStore, dedup, autoReporter, killSwitch, autoCfg,
	)
	go autoController.RunCleanup(ctx)

	if client != nil && autoReporter != nil {
		decisionReporter := autonomy.NewDecisionReporter(
			autoController.Decisions(), autoReporter, client.ServiceClient(), agentIDBytes,
		)
		go decisionReporter.Run(ctx)
	} else {
		// Drain decisions to prevent channel fill-up when offline.
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case _, ok := <-autoController.Decisions():
					if !ok {
						return
					}
				}
			}
		}()
	}

	// ── Event fanout: batcher + local rule engine ────────────────────────────
	// Events are forwarded to both the batcher (for server send) and the
	// autonomy controller (for local evaluation). The controller processes
	// events inline — it parses the raw JSON and evaluates rules.
	//
	// The EventMerger sits between the collector manager and the batcher.
	// It deduplicates overlapping sources (eBPF+netlink, eBPF+auditd) within
	// a 300ms window, enriching eBPF network events with src_ip/src_port from
	// netlink and dropping auditd duplicates of eBPF execve/openat.
	evMerger := merger.New(300 * time.Millisecond)

	batcher := transport.NewBatcher(cfg.BatchSize, cfg.BatchTimeout)
	batcherCh := make(chan collector.RawEvent, fanInBufSize)

	var batcherWg sync.WaitGroup
	// Track the merger goroutine so shutdown waits for flushAll to complete.
	batcherWg.Add(1)
	go func() {
		defer batcherWg.Done()
		evMerger.Run(ctx, mgr.Events())
	}()

	batcherWg.Add(1)
	go func() {
		defer batcherWg.Done()
		err := batcher.Run(ctx, batcherCh, func(batch []collector.RawEvent) error {
			return sendBatch(ctx, log, client, buf, ch, mp, batch)
		})
		if err != nil && err != context.Canceled {
			log.Error("batcher exited with error", "err", err)
		}
	}()

	// Fanout goroutine: reads from merger (deduplicated events), sends to batcher,
	// and feeds the autonomy controller.
	batcherWg.Add(1)
	go func() {
		defer batcherWg.Done()
		defer close(batcherCh)
		for ev := range evMerger.Events() {
			// Forward to batcher (blocking — batcher drains fast enough in normal operation;
			// if it blocks, backpressure propagates to collectors which is preferable to event loss).
			select {
			case batcherCh <- ev:
			case <-ctx.Done():
				return
			}

			// Feed the autonomy controller with a copy of the parsed event.
			if autoController != nil && ev.Raw != nil {
				var parsed map[string]interface{}
				if err := json.Unmarshal(ev.Raw, &parsed); err == nil {
					parsed["_source"] = ev.Source
					parsed["_timestamp"] = ev.Timestamp
					autoController.ProcessEvent(parsed)
				}
			}
		}
	}()

	// ── Collector health reporter ─────────────────────────────────────────────
	// Every 30s, push a synthetic event carrying collector health data so the
	// server can expose it via GET /agents/{cn}/collectors.
	batcherWg.Add(1)
	go func() {
		defer batcherWg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				healths := mgr.Healths()
				raw, err := json.Marshal(healths)
				if err != nil {
					continue
				}
				ev := collector.RawEvent{
					Source:    "collector_health",
					OS:        "linux",
					Timestamp: time.Now().UnixNano(),
					Raw:       raw,
				}
				// Guard against a send-on-closed-channel panic: batcherCh is closed
				// by the fanout goroutine's defer, which may race with this ticker.
				func() {
					defer func() { recover() }() //nolint:errcheck
					select {
					case batcherCh <- ev:
					case <-ctx.Done():
					}
				}()
				if ctx.Err() != nil {
					return
				}
			}
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

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// drainBuffer ships buffered events before shutdown using Replay+AckUntil so that
// events are never deleted before successful delivery (no re-push race on failure).
func drainBuffer(ctx context.Context, log *slog.Logger, client *transport.GRPCClient, buf *buffer.Buffer) {
	var lastAckID int64
	for {
		select {
		case <-ctx.Done():
			log.Warn("drain timeout — some buffered events may not have been sent")
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
				log.Warn("proto unmarshal failed during drain, skipping", "err", err)
				continue
			}
			pbEvents = append(pbEvents, &pb)
		}

		maxID := entries[len(entries)-1].ID

		if len(pbEvents) == 0 {
			// All entries in this page were corrupt — ack and advance.
			if err := buf.AckUntil(maxID); err != nil {
				log.Warn("buffer ack failed after corrupt page", "err", err)
			}
			lastAckID = maxID
			continue
		}

		if err := client.SendBatch(ctx, pbEvents); err != nil {
			log.Warn("drain send failed — events remain buffered for next start", "err", err, "count", len(entries))
			return
		}

		if err := buf.AckUntil(maxID); err != nil {
			log.Warn("buffer ack failed after successful send", "err", err)
		}
		lastAckID = maxID
		log.Info("drained buffered events", "count", len(pbEvents))
	}
}
