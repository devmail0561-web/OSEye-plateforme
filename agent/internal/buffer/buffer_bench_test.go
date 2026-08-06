package buffer

import (
	"fmt"
	"testing"
)

func makePayloads(n, size int) [][]byte {
	payloads := make([][]byte, n)
	for i := range payloads {
		p := make([]byte, size)
		for j := range p {
			p[j] = byte(i + j)
		}
		payloads[i] = p
	}
	return payloads
}

// BenchmarkPush_1000 measures batch insert of 1000 events.
// With CGO build tag: mattn/go-sqlite3 + WAL. Without: modernc (pure Go).
// Target: <1ms per transaction.
func BenchmarkPush_1000_modernc(b *testing.B) {
	buf, err := Open(":memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer buf.Close()

	payloads := makePayloads(1000, 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := buf.Push(payloads); err != nil {
			b.Fatal(err)
		}
		// Pop to keep the table small across iterations
		if _, err := buf.Pop(1000); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPop_1000_modernc measures batch read+delete of 1000 events.
func BenchmarkPop_1000_modernc(b *testing.B) {
	buf, err := Open(":memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer buf.Close()

	payloads := makePayloads(1000, 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		if err := buf.Push(payloads); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		if _, err := buf.Pop(1000); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPush_sizes sweeps batch sizes to find the throughput curve.
func BenchmarkPush_sizes(b *testing.B) {
	for _, n := range []int{10, 100, 500, 1000} {
		n := n
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			buf, err := Open(":memory:")
			if err != nil {
				b.Fatal(err)
			}
			defer buf.Close()
			payloads := makePayloads(n, 512)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := buf.Push(payloads); err != nil {
					b.Fatal(err)
				}
				if _, err := buf.Pop(n); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
