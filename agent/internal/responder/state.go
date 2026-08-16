//go:build linux

// Package responder executes server-ordered response actions (block IP,
// quarantine file, kill process) and persists their state locally so that
// in-progress actions survive agent restarts.
package responder

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

// maxPayloadBytes is the maximum serialized payload size accepted by Save (1 MB).
const maxPayloadBytes = 1 << 20

const stateSchema = `
CREATE TABLE IF NOT EXISTS active_actions (
    command_id   TEXT    PRIMARY KEY,
    command_type TEXT    NOT NULL,
    payload      TEXT    NOT NULL,  -- JSON
    status       TEXT    NOT NULL DEFAULT 'pending',  -- pending|executed|failed|rolled_back
    created_at   INTEGER NOT NULL,
    executed_at  INTEGER
);
`

// ActionState is a persisted record of a response action.
type ActionState struct {
	CommandID   string
	CommandType string
	Payload     map[string]any
	Status      string
	CreatedAt   int64
	ExecutedAt  *int64
}

// StateStore persists active response actions in a dedicated SQLite table.
// It shares the same DB file as the event buffer but uses a separate table.
type StateStore struct {
	db *sql.DB
}

// OpenStateStore opens (or creates) the state table in the given DB file.
func OpenStateStore(path string) (*StateStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("responder: open state db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("responder: set wal mode: %w", err)
	}
	if _, err := db.Exec(stateSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("responder: init state schema: %w", err)
	}
	return &StateStore{db: db}, nil
}

func (s *StateStore) Close() error { return s.db.Close() }

// Save persists an action before execution (status = "pending").
func (s *StateStore) Save(a ActionState) error {
	payload, err := json.Marshal(a.Payload)
	if err != nil {
		return fmt.Errorf("responder: marshal payload: %w", err)
	}
	if len(payload) > maxPayloadBytes {
		log.Printf("responder: Save: payload too large for command %q: %d bytes (max %d)",
			a.CommandID, len(payload), maxPayloadBytes)
		return fmt.Errorf("responder: payload exceeds maximum size (%d > %d bytes)",
			len(payload), maxPayloadBytes)
	}
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO active_actions
		 (command_id, command_type, payload, status, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		a.CommandID, a.CommandType, string(payload), a.Status, a.CreatedAt,
	)
	return err
}

// MarkExecuted updates status and executed_at timestamp.
func (s *StateStore) MarkExecuted(commandID string, ts int64) error {
	_, err := s.db.Exec(
		`UPDATE active_actions SET status='executed', executed_at=? WHERE command_id=?`,
		ts, commandID,
	)
	return err
}

// MarkFailed records a failure.
func (s *StateStore) MarkFailed(commandID string) error {
	_, err := s.db.Exec(
		`UPDATE active_actions SET status='failed' WHERE command_id=?`,
		commandID,
	)
	return err
}

// MarkRolledBack records a rollback.
func (s *StateStore) MarkRolledBack(commandID string) error {
	_, err := s.db.Exec(
		`UPDATE active_actions SET status='rolled_back' WHERE command_id=?`,
		commandID,
	)
	return err
}

// GetExecuted returns all executed actions for rollback recovery on restart.
func (s *StateStore) GetExecuted() ([]ActionState, error) {
	rows, err := s.db.Query(
		`SELECT command_id, command_type, payload, status, created_at, executed_at
		 FROM active_actions WHERE status='executed'`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var actions []ActionState
	for rows.Next() {
		var a ActionState
		var payload string
		var execAt sql.NullInt64
		if err := rows.Scan(&a.CommandID, &a.CommandType, &payload,
			&a.Status, &a.CreatedAt, &execAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(payload), &a.Payload); err != nil {
			return nil, err
		}
		if execAt.Valid {
			a.ExecutedAt = &execAt.Int64
		}
		actions = append(actions, a)
	}
	return actions, rows.Err()
}

// nowNs returns current time in Unix nanoseconds.
func nowNs() int64 { return time.Now().UnixNano() }
