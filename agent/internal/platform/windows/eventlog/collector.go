//go:build windows

// Package eventlog tails the Windows Security, System, and Application
// event logs via ReadEventLog, emitting each record as a JSON RawEvent.
package eventlog

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/oseye/agent/internal/collector"
	"golang.org/x/sys/windows"
)

const (
	eventLogSourceSecurity    = "Security"
	eventLogSourceSystem      = "System"
	eventLogSourceApplication = "Application"

	eventTypeError       = 1
	eventTypeWarning     = 2
	eventTypeInformation = 4
	eventTypeAuditSuccess = 8
	eventTypeAuditFailure = 16

	readSeek    = 0x0002
	readForward = 0x0004
	readNewest  = 0x0008

	pollInterval = 5 * time.Second
	readBufSize  = 65536
)

var (
	modadvapi32el       = windows.NewLazySystemDLL("advapi32.dll")
	procOpenEventLogW   = modadvapi32el.NewProc("OpenEventLogW")
	procReadEventLogW   = modadvapi32el.NewProc("ReadEventLogW")
	procCloseEventLog   = modadvapi32el.NewProc("CloseEventLog")
	procGetNumberOfEventLogRecords = modadvapi32el.NewProc("GetNumberOfEventLogRecords")
)

// eventLogRecord mirrors EVENTLOGRECORD (variable-length structure).
type eventLogRecord struct {
	Length              uint32
	Reserved            uint32
	RecordNumber        uint32
	TimeGenerated       uint32
	TimeWritten         uint32
	EventID             uint32
	EventType           uint16
	NumStrings          uint16
	EventCategory       uint16
	ReservedFlags       uint16
	ClosingRecordNumber uint32
	StringOffset        uint32
	UserSidLength       uint32
	UserSidOffset       uint32
	DataLength          uint32
	DataOffset          uint32
}

// Collector tails Windows Event Logs.
type Collector struct {
	logger   *slog.Logger
	sources  []string
	stopCh   chan struct{}
	running  bool
	throttle atomic.Value
}

var _ collector.Collector = (*Collector)(nil)

func New(logger *slog.Logger) (*Collector, error) {
	c := &Collector{
		logger:  logger,
		sources: []string{eventLogSourceSecurity, eventLogSourceSystem},
		stopCh:  make(chan struct{}),
	}
	c.throttle.Store(1.0)
	return c, nil
}

func (c *Collector) Name() string { return "eventlog" }

func (c *Collector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	c.running = true
	go c.run(ctx, out)
	return nil
}

func (c *Collector) Stop() error {
	if c.running {
		close(c.stopCh)
		c.running = false
	}
	return nil
}

func (c *Collector) SetThrottle(f float64) { c.throttle.Store(f) }

func (c *Collector) Health() collector.CollectorHealth {
	return collector.CollectorHealth{Running: c.running}
}

type winLogEvent struct {
	Source      string `json:"source"`
	RecordNum   uint32 `json:"record_num"`
	EventID     uint32 `json:"event_id"`
	EventType   string `json:"event_type"`
	Category    uint16 `json:"category"`
	TimeWritten int64  `json:"timestamp_ns"`
}

func eventTypeName(t uint16) string {
	switch t {
	case eventTypeError:
		return "error"
	case eventTypeWarning:
		return "warning"
	case eventTypeInformation:
		return "information"
	case eventTypeAuditSuccess:
		return "audit_success"
	case eventTypeAuditFailure:
		return "audit_failure"
	default:
		return "unknown"
	}
}

func (c *Collector) run(ctx context.Context, out chan<- collector.RawEvent) {
	// Track last read record per source
	lastRecord := make(map[string]uint32)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		if f, _ := c.throttle.Load().(float64); f > 0 {
			for _, src := range c.sources {
				c.readSource(ctx, src, lastRecord, out)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
		}
	}
}

func (c *Collector) readSource(ctx context.Context, source string, lastRecord map[string]uint32, out chan<- collector.RawEvent) {
	namePtr, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return
	}
	handle, _, err := procOpenEventLogW.Call(0, uintptr(unsafe.Pointer(namePtr)))
	if handle == 0 {
		c.logger.Debug("eventlog open failed", "source", source, "err", err)
		return
	}
	defer procCloseEventLog.Call(handle)

	buf := make([]byte, readBufSize)
	var read, needed uint32
	flags := uint32(readForward | readNewest)
	if last, ok := lastRecord[source]; ok {
		flags = readForward | readSeek
		_ = last
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
		}

		r, _, _ := procReadEventLogW.Call(
			handle,
			uintptr(flags),
			0,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&read)),
			uintptr(unsafe.Pointer(&needed)),
		)
		if r == 0 || read == 0 {
			break
		}

		// Parse records from buffer
		offset := uint32(0)
		for offset < read {
			if offset+uint32(unsafe.Sizeof(eventLogRecord{})) > read {
				break
			}
			rec := (*eventLogRecord)(unsafe.Pointer(&buf[offset]))
			if rec.Length == 0 || offset+rec.Length > read {
				break
			}

			ev := winLogEvent{
				Source:      source,
				RecordNum:   rec.RecordNumber,
				EventID:     rec.EventID & 0xFFFF,
				EventType:   eventTypeName(rec.EventType),
				Category:    rec.EventCategory,
				TimeWritten: int64(rec.TimeWritten) * int64(time.Second),
			}
			lastRecord[source] = rec.RecordNumber

			b, _ := json.Marshal(ev)
			select {
			case out <- collector.RawEvent{
				Source:    "eventlog",
				OS:        "windows",
				Timestamp: time.Now().UnixNano(),
				Raw:       b,
			}:
			default:
			}
			offset += rec.Length
		}
		flags = readForward // subsequent reads are sequential
	}
}
