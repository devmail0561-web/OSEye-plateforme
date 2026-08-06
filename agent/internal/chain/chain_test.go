package chain

import (
	"bytes"
	"testing"
)

func TestNew(t *testing.T) {
	c := New()
	got := c.Current()
	want := make([]byte, 32)
	if !bytes.Equal(got, want) {
		t.Errorf("New(): initial hash = %x, want all zeros", got)
	}
}

func TestAppendDeterminism(t *testing.T) {
	c1 := New()
	c2 := New()

	payload := []byte("test event payload")
	h1 := c1.Append(payload)
	h2 := c2.Append(payload)

	if !bytes.Equal(h1, h2) {
		t.Errorf("Append is not deterministic: %x != %x", h1, h2)
	}
}

func TestAppendChaining(t *testing.T) {
	c := New()

	h1 := c.Append([]byte("event-1"))
	h2 := c.Append([]byte("event-2"))

	if bytes.Equal(h1, h2) {
		t.Error("consecutive Append calls produced the same hash")
	}

	// Verify current matches last append
	if !bytes.Equal(c.Current(), h2) {
		t.Error("Current() does not match last Append result")
	}
}

func TestAppendOrderMatters(t *testing.T) {
	c1 := New()
	c2 := New()

	c1.Append([]byte("a"))
	h1 := c1.Append([]byte("b"))

	c2.Append([]byte("b"))
	h2 := c2.Append([]byte("a"))

	if bytes.Equal(h1, h2) {
		t.Error("hash chain is order-independent; expected order to matter")
	}
}

func TestReset(t *testing.T) {
	c := New()
	c.Append([]byte("some data"))

	nonZero := c.Current()
	if bytes.Equal(nonZero, make([]byte, 32)) {
		t.Fatal("expected non-zero hash after Append")
	}

	c.Reset()
	got := c.Current()
	if !bytes.Equal(got, make([]byte, 32)) {
		t.Errorf("after Reset, Current() = %x, want all zeros", got)
	}
}

func TestAppendReturnLen(t *testing.T) {
	c := New()
	h := c.Append([]byte("data"))
	if len(h) != 32 {
		t.Errorf("Append returned %d bytes, want 32", len(h))
	}
}

func TestAppendEmptyPayload(t *testing.T) {
	c := New()
	h := c.Append([]byte{})
	if len(h) != 32 {
		t.Errorf("Append with empty payload returned %d bytes, want 32", len(h))
	}
	if bytes.Equal(h, make([]byte, 32)) {
		t.Error("hash of empty payload over zero chain should not be all zeros")
	}
}
