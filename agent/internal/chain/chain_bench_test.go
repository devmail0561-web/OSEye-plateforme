package chain

import (
	"testing"
)

var sink []byte // prevent dead-code elimination

// BenchmarkAppend_1KB measures BLAKE3 hash chain on 1 KB payloads.
// Target: >500 MB/s throughput (500k × 1KB events/s).
func BenchmarkAppend_1KB(b *testing.B) {
	c := New()
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink = c.Append(payload)
	}
}

// BenchmarkAppend_100B measures throughput on small 100-byte payloads.
func BenchmarkAppend_100B(b *testing.B) {
	c := New()
	payload := make([]byte, 100)
	b.SetBytes(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink = c.Append(payload)
	}
}

// BenchmarkAppend_Batch1000 measures throughput when processing 1000 events per batch.
// This is the real production batch size.
func BenchmarkAppend_Batch1000(b *testing.B) {
	c := New()
	payload := make([]byte, 1024)
	results := make([][]byte, 1000)
	b.SetBytes(1000 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 1000; j++ {
			results[j] = c.Append(payload)
		}
	}
	sink = results[0]
}

// BenchmarkAppend_Parallel measures concurrent chain updates under lock contention.
func BenchmarkAppend_Parallel(b *testing.B) {
	c := New()
	payload := make([]byte, 1024)
	b.SetBytes(1024)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sink = c.Append(payload)
		}
	})
}
