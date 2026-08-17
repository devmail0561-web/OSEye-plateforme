//go:build linux

package syslog

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
)

func TestSyslogCollector_Creation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := NewSyslogCollector("", logger)
	if err != nil {
		t.Fatalf("NewSyslogCollector failed: %v", err)
	}
	if c.Name() != "syslog" {
		t.Errorf("expected 'syslog', got %s", c.Name())
	}
	if c.addr != "127.0.0.1:514" {
		t.Errorf("expected default addr '127.0.0.1:514', got %s", c.addr)
	}
}

func TestSyslogCollector_SetThrottle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewSyslogCollector("", logger)
	c.SetThrottle(0.6)
	h := c.Health()
	if h.ThrottlePct != 60.0 {
		t.Errorf("expected ThrottlePct 60, got %v", h.ThrottlePct)
	}
}

func TestSyslogCollector_Stop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewSyslogCollector("", logger)
	if err := c.Stop(); err != nil {
		t.Errorf("Stop() failed: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Errorf("Stop() second call failed: %v", err)
	}
}

func TestSyslogCollector_ParseRFC3164(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewSyslogCollector("", logger)

	msg := "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
	event, err := c.parseMessage([]byte(msg))
	if err != nil {
		t.Fatalf("parseMessage failed: %v", err)
	}
	if event.Source != "syslog" {
		t.Errorf("expected source 'syslog', got %s", event.Source)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(event.Raw, &payload); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	// facility 4 = auth, severity 2 = critical
	if payload["facility"] != "auth" {
		t.Errorf("expected facility 'auth', got %v", payload["facility"])
	}
	if payload["severity"] != "critical" {
		t.Errorf("expected severity 'critical', got %v", payload["severity"])
	}
}

func TestSyslogCollector_ParseEmpty(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewSyslogCollector("", logger)

	_, err := c.parseMessage([]byte(""))
	if err == nil {
		t.Error("expected error for empty message")
	}
}

func TestSyslogCollector_ReceiveUDP(t *testing.T) {
	// Use a random ephemeral port to avoid conflicts
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := NewSyslogCollector("127.0.0.1:0", logger)
	if err != nil {
		t.Fatalf("NewSyslogCollector failed: %v", err)
	}

	// Find an available port
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind UDP: %v", err)
	}
	port := ln.LocalAddr().(*net.UDPAddr).Port
	ln.Close()

	c.addr = fmt.Sprintf("127.0.0.1:%d", port)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	out := make(chan collector.RawEvent, 10)
	go func() {
		c.Start(ctx, out) //nolint:errcheck
	}()

	// Give collector time to bind
	time.Sleep(100 * time.Millisecond)

	// Send a syslog message
	conn, err := net.Dial("udp", c.addr)
	if err != nil {
		t.Skipf("cannot connect UDP: %v", err)
	}
	defer conn.Close()

	msg := "<134>Aug  6 21:00:00 testhost myapp[123]: test message from unit test"
	if _, err := fmt.Fprint(conn, msg); err != nil {
		t.Fatalf("send UDP failed: %v", err)
	}

	select {
	case event := <-out:
		if event.Source != "syslog" {
			t.Errorf("expected source 'syslog', got %s", event.Source)
		}
		t.Logf("Received syslog event: %s", string(event.Raw))
	case <-time.After(800 * time.Millisecond):
		t.Error("did not receive syslog event within timeout")
	}
}
