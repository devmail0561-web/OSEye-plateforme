package buffer

import (
	"bytes"
	"testing"
)

func openMemory(t *testing.T) *Buffer {
	t.Helper()
	b, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:) error = %v", err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func TestOpenAndClose(t *testing.T) {
	b := openMemory(t)
	if b == nil {
		t.Fatal("expected non-nil Buffer")
	}
}

func TestPushPopSingle(t *testing.T) {
	b := openMemory(t)

	event := []byte("serialised event payload")
	if err := b.Push([][]byte{event}); err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	got, err := b.Pop(1)
	if err != nil {
		t.Fatalf("Pop() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Pop() returned %d items, want 1", len(got))
	}
	if !bytes.Equal(got[0], event) {
		t.Errorf("Pop() payload = %q, want %q", got[0], event)
	}
}

func TestPushPopBatch(t *testing.T) {
	b := openMemory(t)

	events := [][]byte{
		[]byte("event-1"),
		[]byte("event-2"),
		[]byte("event-3"),
	}
	if err := b.Push(events); err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	got, err := b.Pop(3)
	if err != nil {
		t.Fatalf("Pop() error = %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("Pop() returned %d items, want 3", len(got))
	}
	for i, ev := range events {
		if !bytes.Equal(got[i], ev) {
			t.Errorf("Pop()[%d] = %q, want %q", i, got[i], ev)
		}
	}
}

func TestFIFOOrder(t *testing.T) {
	b := openMemory(t)

	b.Push([][]byte{[]byte("first")})
	b.Push([][]byte{[]byte("second")})
	b.Push([][]byte{[]byte("third")})

	got, err := b.Pop(3)
	if err != nil {
		t.Fatalf("Pop() error = %v", err)
	}
	expected := []string{"first", "second", "third"}
	for i, want := range expected {
		if string(got[i]) != want {
			t.Errorf("FIFO[%d] = %q, want %q", i, got[i], want)
		}
	}
}

func TestPopMoreThanAvailable(t *testing.T) {
	b := openMemory(t)

	b.Push([][]byte{[]byte("only-one")})

	got, err := b.Pop(10)
	if err != nil {
		t.Fatalf("Pop() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Pop(10) on buffer of 1 returned %d items, want 1", len(got))
	}
}

func TestPopEmpty(t *testing.T) {
	b := openMemory(t)

	got, err := b.Pop(5)
	if err != nil {
		t.Fatalf("Pop() on empty buffer error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Pop() on empty buffer returned %d items, want 0", len(got))
	}
}

func TestLen(t *testing.T) {
	b := openMemory(t)

	n, err := b.Len()
	if err != nil {
		t.Fatalf("Len() error = %v", err)
	}
	if n != 0 {
		t.Errorf("Len() = %d, want 0 on empty buffer", n)
	}

	b.Push([][]byte{[]byte("a"), []byte("b"), []byte("c")})

	n, err = b.Len()
	if err != nil {
		t.Fatalf("Len() error = %v", err)
	}
	if n != 3 {
		t.Errorf("Len() = %d, want 3", n)
	}

	b.Pop(2)

	n, err = b.Len()
	if err != nil {
		t.Fatalf("Len() error = %v", err)
	}
	if n != 1 {
		t.Errorf("Len() after Pop(2) = %d, want 1", n)
	}
}

func TestPopDequeues(t *testing.T) {
	b := openMemory(t)

	b.Push([][]byte{[]byte("e1"), []byte("e2")})
	b.Pop(2)

	n, _ := b.Len()
	if n != 0 {
		t.Errorf("after Pop(2) Len() = %d, want 0", n)
	}
}

func TestPushEmptySlice(t *testing.T) {
	b := openMemory(t)

	if err := b.Push([][]byte{}); err != nil {
		t.Errorf("Push(empty) should not error, got %v", err)
	}
	n, _ := b.Len()
	if n != 0 {
		t.Errorf("Len() after Push(empty) = %d, want 0", n)
	}
}
