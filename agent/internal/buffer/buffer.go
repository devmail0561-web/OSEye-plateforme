//go:build !cgo

package buffer

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no CGO required)
)

const schema = `
CREATE TABLE IF NOT EXISTS buffer (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    payload    BLOB    NOT NULL,
    created_at INTEGER NOT NULL
);
`

// Buffer is a persistent offline event queue backed by SQLite.
// Events are stored as raw serialized blobs and consumed in FIFO order.
type Buffer struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path and initialises the schema.
// Use ":memory:" for an in-process ephemeral buffer (tests).
func Open(path string) (*Buffer, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("buffer: open db: %w", err)
	}

	// Enforce a single writer to avoid SQLITE_BUSY on concurrent access.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("buffer: set wal mode: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("buffer: init schema: %w", err)
	}

	return &Buffer{db: db}, nil
}

// Close releases the database connection.
func (b *Buffer) Close() error {
	return b.db.Close()
}

// Push inserts a batch of serialised events in a single transaction.
// An empty slice is a no-op.
func (b *Buffer) Push(events [][]byte) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := b.db.Begin()
	if err != nil {
		return fmt.Errorf("buffer: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.Prepare(`INSERT INTO buffer (payload, created_at) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("buffer: prepare insert: %w", err)
	}
	defer stmt.Close()

	now := time.Now().UnixNano()
	for _, ev := range events {
		if _, err := stmt.Exec(ev, now); err != nil {
			return fmt.Errorf("buffer: insert event: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("buffer: commit tx: %w", err)
	}
	return nil
}

// Pop reads and deletes up to n events from the buffer in insertion order (FIFO).
// Returns fewer than n items when the buffer has fewer than n events.
func (b *Buffer) Pop(n int) ([][]byte, error) {
	if n <= 0 {
		return nil, nil
	}

	tx, err := b.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("buffer: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	rows, err := tx.Query(
		`SELECT id, payload FROM buffer ORDER BY id ASC LIMIT ?`, n,
	)
	if err != nil {
		return nil, fmt.Errorf("buffer: select events: %w", err)
	}

	ids := make([]int64, 0, n)
	payloads := make([][]byte, 0, n)
	for rows.Next() {
		var id int64
		var payload []byte
		if err := rows.Scan(&id, &payload); err != nil {
			rows.Close()
			return nil, fmt.Errorf("buffer: scan row: %w", err)
		}
		ids = append(ids, id)
		payloads = append(payloads, payload)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("buffer: rows error: %w", err)
	}

	if len(ids) > 0 {
		// IDs are AUTOINCREMENT FIFO — a single range DELETE replaces N individual deletes.
		if _, err := tx.Exec(`DELETE FROM buffer WHERE id <= ?`, ids[len(ids)-1]); err != nil {
			return nil, fmt.Errorf("buffer: delete events: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("buffer: commit pop tx: %w", err)
	}
	return payloads, nil
}

// Len returns the number of events currently in the buffer.
func (b *Buffer) Len() (int, error) {
	var count int
	if err := b.db.QueryRow(`SELECT COUNT(*) FROM buffer`).Scan(&count); err != nil {
		return 0, fmt.Errorf("buffer: count: %w", err)
	}
	return count, nil
}

// Entry holds a buffer row with its database ID and serialised payload.
type Entry struct {
	ID      int64
	Payload []byte
}

// Replay returns up to n entries with id > afterID without removing them.
// Use afterID=0 to start from the beginning of the buffer.
// This enables replay-on-reconnect: read without deleting, ack after successful send.
func (b *Buffer) Replay(afterID int64, n int) ([]Entry, error) {
	if n <= 0 {
		return nil, nil
	}

	rows, err := b.db.Query(
		`SELECT id, payload FROM buffer WHERE id > ? ORDER BY id ASC LIMIT ?`,
		afterID, n,
	)
	if err != nil {
		return nil, fmt.Errorf("buffer: replay query: %w", err)
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Payload); err != nil {
			return nil, fmt.Errorf("buffer: replay scan: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("buffer: replay rows: %w", err)
	}
	return entries, nil
}

// AckUntil deletes all buffer entries with id <= maxID.
// Call after a successful SendBatch to confirm delivery and reclaim space.
func (b *Buffer) AckUntil(maxID int64) error {
	if _, err := b.db.Exec(`DELETE FROM buffer WHERE id <= ?`, maxID); err != nil {
		return fmt.Errorf("buffer: ack until %d: %w", maxID, err)
	}
	return nil
}
