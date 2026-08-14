//go:build linux

// Package ebpf provides a collector that attaches eBPF tracepoint programs to
// capture execve, openat and connect syscalls. The BPF objects are compiled
// offline with bpf2go (go generate) and embedded in the binary.
//
// To regenerate the BPF objects after editing the .bpf.c programs:
//
//	//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" execve ./programs/execve.bpf.c
//	//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" openat  ./programs/openat.bpf.c
//	//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" connect ./programs/connect.bpf.c
package ebpf

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sync/errgroup"
)

// EBPFEvent is the Go-side representation of a kernel event read from the
// perf ring buffer.
type EBPFEvent struct {
	Type        string `json:"event_type"` // "execve" | "openat" | "connect"
	TimestampNs uint64 `json:"timestamp_ns"`
	Pid         uint32 `json:"pid"`
	Ppid        uint32 `json:"ppid,omitempty"`
	Uid         uint32 `json:"uid"`
	Gid         uint32 `json:"gid,omitempty"`
	Comm        string `json:"comm"`
	Filename    string `json:"filename,omitempty"`
	Flags       int32  `json:"flags,omitempty"`
	Family      uint16 `json:"family,omitempty"`
	DstIP       string `json:"dst_ip,omitempty"`
	DstPort     uint16 `json:"dst_port,omitempty"`
}

// EBPFLoader manages the lifecycle of the three eBPF programs and their perf
// readers. It is created by NewLoader and must be closed with Close().
type EBPFLoader struct {
	execveObjs  execveObjects
	openatObjs  openatObjects
	connectObjs connectObjects
	links       []link.Link
	readers     []*perf.Reader
	closeOnce   sync.Once
}

// NewLoader loads and attaches all three eBPF programs. Returns an error when
// the kernel does not support eBPF (kernel < 5.8) or when the process lacks
// CAP_BPF / CAP_PERFMON. Callers should treat any error as non-fatal and fall
// back to a no-op collector.
func NewLoader() (*EBPFLoader, error) {
	l := &EBPFLoader{}

	// ── execve ──────────────────────────────────────────────────────────────
	if err := loadExecveObjects(&l.execveObjs, nil); err != nil {
		return nil, fmt.Errorf("ebpf: load execve objects: %w", err)
	}
	execveLink, err := link.Tracepoint("syscalls", "sys_enter_execve", l.execveObjs.HandleExecve, nil)
	if err != nil {
		l.execveObjs.Close()
		return nil, fmt.Errorf("ebpf: attach execve tracepoint: %w", err)
	}
	l.links = append(l.links, execveLink)

	execveReader, err := perf.NewReader(l.execveObjs.ExecveEvents, 4096*os.Getpagesize())
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("ebpf: execve perf reader: %w", err)
	}
	l.readers = append(l.readers, execveReader)

	// ── openat ──────────────────────────────────────────────────────────────
	if err := loadOpenatObjects(&l.openatObjs, nil); err != nil {
		l.Close()
		return nil, fmt.Errorf("ebpf: load openat objects: %w", err)
	}
	openatLink, err := link.Tracepoint("syscalls", "sys_enter_openat", l.openatObjs.HandleOpenat, nil)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("ebpf: attach openat tracepoint: %w", err)
	}
	l.links = append(l.links, openatLink)

	openatReader, err := perf.NewReader(l.openatObjs.OpenatEvents, 4096*os.Getpagesize())
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("ebpf: openat perf reader: %w", err)
	}
	l.readers = append(l.readers, openatReader)

	// ── connect ─────────────────────────────────────────────────────────────
	if err := loadConnectObjects(&l.connectObjs, nil); err != nil {
		l.Close()
		return nil, fmt.Errorf("ebpf: load connect objects: %w", err)
	}
	connectLink, err := link.Tracepoint("syscalls", "sys_enter_connect", l.connectObjs.HandleConnect, nil)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("ebpf: attach connect tracepoint: %w", err)
	}
	l.links = append(l.links, connectLink)

	connectReader, err := perf.NewReader(l.connectObjs.ConnectEvents, 4096*os.Getpagesize())
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("ebpf: connect perf reader: %w", err)
	}
	l.readers = append(l.readers, connectReader)

	return l, nil
}

// ReadEvents returns a channel that receives eBPF events from all three
// programs. The channel is closed when ctx is cancelled or an unrecoverable
// reader error occurs. It uses an errgroup so that out is closed exactly once,
// by the orchestrating goroutine after all producers have exited — avoiding
// "send on closed channel" panics.
func (l *EBPFLoader) ReadEvents(ctx context.Context) <-chan EBPFEvent {
	out := make(chan EBPFEvent, 256)

	go func() {
		g, gctx := errgroup.WithContext(ctx)

		var once sync.Once
		closeOut := func() { once.Do(func() { close(out) }) }

		for i, r := range l.readers {
			idx, rd := i, r
			g.Go(func() error {
				for {
					// Unblock rd.Read() when the group context is cancelled.
					// perf.Reader.SetDeadline is the idiomatic cilium/ebpf way to
					// interrupt a blocked Read; closing is handled by Close() / the
					// caller — we must not close rd here to avoid double-close races.
					select {
					case <-gctx.Done():
						rd.SetDeadline(pastDeadline)
						return nil
					default:
					}

					rec, err := rd.Read()
					if err != nil {
						// A deadline error means we were asked to stop — not a real failure.
						if gctx.Err() != nil {
							return nil
						}
						return fmt.Errorf("ebpf reader %d: %w", idx, err)
					}

					ev, ok := parseRecord(idx, rec.RawSample)
					if !ok {
						continue
					}

					select {
					case out <- ev:
					case <-gctx.Done():
						rd.SetDeadline(pastDeadline)
						return nil
					}
				}
			})
		}

		// Wait for all producers to finish, then close the output channel exactly once.
		if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
			// Non-cancellation error: a perf reader crashed or returned an unexpected
			// error. Log it so operators can distinguish a silent collection gap from
			// a clean shutdown. The caller detects shutdown via channel close.
			slog.Error("ebpf reader error", slog.String("error", err.Error()))
		}
		closeOut()
	}()

	return out
}

// pastDeadline is a time in the distant past used to immediately unblock a
// perf.Reader.Read() call via SetDeadline without closing the reader.
var pastDeadline = func() time.Time {
	t, _ := time.Parse(time.RFC3339, "2000-01-01T00:00:00Z")
	return t
}()

// Close releases all eBPF resources. It is safe to call concurrently or more
// than once; the actual teardown runs exactly once via closeOnce.
func (l *EBPFLoader) Close() error {
	l.closeOnce.Do(func() {
		for _, r := range l.readers {
			r.Close()
		}
		for _, lnk := range l.links {
			lnk.Close()
		}
		l.execveObjs.Close()
		l.openatObjs.Close()
		l.connectObjs.Close()
	})
	return nil
}

// parseRecord decodes a raw perf sample into an EBPFEvent.
// idx 0 = execve, 1 = openat, 2 = connect — must match the order in NewLoader.
func parseRecord(idx int, raw []byte) (EBPFEvent, bool) {
	if len(raw) == 0 {
		return EBPFEvent{}, false
	}
	switch idx {
	case 0:
		return parseExecve(raw)
	case 1:
		return parseOpenat(raw)
	case 2:
		return parseConnect(raw)
	}
	return EBPFEvent{}, false
}

// execveKernelEvent matches the C struct execve_event layout.
type execveKernelEvent struct {
	TimestampNs uint64
	Pid         uint32
	Ppid        uint32
	Uid         uint32
	Gid         uint32
	Comm        [16]byte
	Filename    [256]byte
}

func parseExecve(raw []byte) (EBPFEvent, bool) {
	if len(raw) < 296 { // 8+4+4+4+4+16+256 = 296
		return EBPFEvent{}, false
	}
	var k execveKernelEvent
	k.TimestampNs = binary.LittleEndian.Uint64(raw[0:8])
	k.Pid = binary.LittleEndian.Uint32(raw[8:12])
	k.Ppid = binary.LittleEndian.Uint32(raw[12:16])
	k.Uid = binary.LittleEndian.Uint32(raw[16:20])
	k.Gid = binary.LittleEndian.Uint32(raw[20:24])
	copy(k.Comm[:], raw[24:40])
	copy(k.Filename[:], raw[40:296])
	return EBPFEvent{
		Type:        "execve",
		TimestampNs: k.TimestampNs,
		Pid:         k.Pid,
		Ppid:        k.Ppid,
		Uid:         k.Uid,
		Gid:         k.Gid,
		Comm:        nullTerm(k.Comm[:]),
		Filename:    nullTerm(k.Filename[:]),
	}, true
}

// openatKernelEvent matches the C struct openat_event layout.
type openatKernelEvent struct {
	TimestampNs uint64
	Pid         uint32
	Uid         uint32
	Flags       int32
	Comm        [16]byte
	Filename    [256]byte
}

func parseOpenat(raw []byte) (EBPFEvent, bool) {
	if len(raw) < 292 { // 8+4+4+4+16+256
		return EBPFEvent{}, false
	}
	var k openatKernelEvent
	k.TimestampNs = binary.LittleEndian.Uint64(raw[0:8])
	k.Pid = binary.LittleEndian.Uint32(raw[8:12])
	k.Uid = binary.LittleEndian.Uint32(raw[12:16])
	k.Flags = int32(binary.LittleEndian.Uint32(raw[16:20]))
	copy(k.Comm[:], raw[20:36])
	copy(k.Filename[:], raw[36:292])
	return EBPFEvent{
		Type:        "openat",
		TimestampNs: k.TimestampNs,
		Pid:         k.Pid,
		Uid:         k.Uid,
		Flags:       k.Flags,
		Comm:        nullTerm(k.Comm[:]),
		Filename:    nullTerm(k.Filename[:]),
	}, true
}

// connectKernelEvent matches the C struct connect_event layout.
type connectKernelEvent struct {
	TimestampNs uint64
	Pid         uint32
	Uid         uint32
	Family      uint16
	DstPort     uint16
	DstIP       [16]byte
	Comm        [16]byte
}

func parseConnect(raw []byte) (EBPFEvent, bool) {
	if len(raw) < 52 { // 8+4+4+2+2+16+16
		return EBPFEvent{}, false
	}
	var k connectKernelEvent
	k.TimestampNs = binary.LittleEndian.Uint64(raw[0:8])
	k.Pid = binary.LittleEndian.Uint32(raw[8:12])
	k.Uid = binary.LittleEndian.Uint32(raw[12:16])
	k.Family = binary.LittleEndian.Uint16(raw[16:18])
	k.DstPort = binary.BigEndian.Uint16(raw[18:20]) // network byte order
	copy(k.DstIP[:], raw[20:36])
	copy(k.Comm[:], raw[36:52])

	var dstIP string
	if k.Family == 2 { // AF_INET
		dstIP = net.IP(k.DstIP[:4]).String()
	} else if k.Family == 10 { // AF_INET6
		dstIP = net.IP(k.DstIP[:]).String()
	}

	return EBPFEvent{
		Type:        "connect",
		TimestampNs: k.TimestampNs,
		Pid:         k.Pid,
		Uid:         k.Uid,
		Family:      k.Family,
		DstIP:       dstIP,
		DstPort:     k.DstPort,
		Comm:        nullTerm(k.Comm[:]),
	}, true
}

// nullTerm converts a null-terminated C byte array to a Go string.
func nullTerm(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// MarshalEvent serialises an EBPFEvent to JSON for use as RawEvent.Raw.
func MarshalEvent(ev EBPFEvent) ([]byte, error) {
	return json.Marshal(ev)
}
