//go:build linux && !ebpf_generated

// This file provides stub types so the package compiles without running
// bpf2go (which requires clang). When bpf2go has been run (go generate ./...),
// the generated *_bpfel.go / *_bpfeb.go files take precedence via build tags.
//
// To regenerate from the .bpf.c programs:
//
//	apt install clang llvm linux-headers-$(uname -r)
//	cd agent && go generate ./internal/platform/linux/ebpf/
package ebpf

import (
	"github.com/cilium/ebpf"
)

// ── execve ───────────────────────────────────────────────────────────────────

type execveObjects struct {
	ExecveEvents *ebpf.Map     `ebpf:"execve_events"`
	HandleExecve *ebpf.Program `ebpf:"handle_execve"`
}

func (o *execveObjects) Close() {
	if o.ExecveEvents != nil {
		o.ExecveEvents.Close()
	}
	if o.HandleExecve != nil {
		o.HandleExecve.Close()
	}
}

func loadExecveObjects(obj *execveObjects, _ interface{}) error {
	return &ebpf.VerifierError{Log: []string{"stub: bpf2go not run — compile with clang first"}}
}

// ── openat ───────────────────────────────────────────────────────────────────

type openatObjects struct {
	OpenatEvents *ebpf.Map     `ebpf:"openat_events"`
	HandleOpenat *ebpf.Program `ebpf:"handle_openat"`
}

func (o *openatObjects) Close() {
	if o.OpenatEvents != nil {
		o.OpenatEvents.Close()
	}
	if o.HandleOpenat != nil {
		o.HandleOpenat.Close()
	}
}

func loadOpenatObjects(obj *openatObjects, _ interface{}) error {
	return &ebpf.VerifierError{Log: []string{"stub: bpf2go not run — compile with clang first"}}
}

// ── connect ──────────────────────────────────────────────────────────────────

type connectObjects struct {
	ConnectEvents *ebpf.Map     `ebpf:"connect_events"`
	HandleConnect *ebpf.Program `ebpf:"connect_events"`
}

func (o *connectObjects) Close() {
	if o.ConnectEvents != nil {
		o.ConnectEvents.Close()
	}
	if o.HandleConnect != nil {
		o.HandleConnect.Close()
	}
}

func loadConnectObjects(obj *connectObjects, _ interface{}) error {
	return &ebpf.VerifierError{Log: []string{"stub: bpf2go not run — compile with clang first"}}
}
