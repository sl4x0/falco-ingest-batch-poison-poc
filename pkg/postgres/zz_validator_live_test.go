// SPDX-License-Identifier: Apache-2.0
//
// VALIDATOR-ONLY test. Not part of upstream and not part of the hunter's PoC.
// It exercises the REAL postgres.Insert against a REAL PostgreSQL 16 carrying the
// exact upstream DDL (falco-event-db-schema/src/setup-database.py create_table),
// rather than the hunter's closed-pool sentinel, so the atomicity of COPY and the
// varchar/uuid column enforcement are observed directly.
//
// Run:  PG_TEST_DSN='postgres://postgres:validator@127.0.0.1:5433/falco' go test -v -run ValidatorLive ./pkg/postgres/
package postgres

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const vLiveIdentity = "shoot--victimproj--victimcluster-123e4567-e89b-12d3-a456-426614174000-garden-dev"

func vLiveEvent() EventStruct {
	return EventStruct{
		Uuid:         "123e4567-e89b-12d3-a456-426614174000",
		Output:       "validator output",
		Priority:     "Notice",
		Rule:         "validator rule",
		Time:         time.Now().UTC().Truncate(time.Microsecond),
		OutputFields: map[string]json.RawMessage{"cluster_id": json.RawMessage(`"` + vLiveIdentity + `"`)},
		Source:       "syscall",
		Tags:         json.RawMessage(`["container"]`),
		Hostname:     "falco-abcde",
	}
}

func vLivePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("PG_TEST_DSN")
	if dsn == "" {
		t.Skip("PG_TEST_DSN not set")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func vLiveCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), "select count(*) from falco_events").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func vLiveTruncate(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), "truncate falco_events"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// Baseline: three valid rows really do persist (so the zero-count cases below are
// rollbacks, not a broken harness).
func TestValidatorLive_BaselineValidBatchPersists(t *testing.T) {
	pool := vLivePool(t)
	pg := &PostgresConfig{dbpool: pool}
	vLiveTruncate(t, pool)

	err := pg.Insert([]EventStruct{vLiveEvent(), vLiveEvent(), vLiveEvent()})
	if err != nil {
		t.Fatalf("valid batch failed: %v", err)
	}
	if n := vLiveCount(t, pool); n != 3 {
		t.Fatalf("expected 3 rows persisted, got %d", n)
	}
	t.Logf("BASELINE: 3 valid rows -> 3 persisted (real Postgres)")
}

// The load-bearing test: 2 valid rows + 1 store-fatal row, in one shared batch,
// against a real DB. Expect an error AND zero rows, i.e. COPY is atomic and the
// whole batch (victims included) is rolled back.
func TestValidatorLive_OneBadRowRollsBackWholeSharedBatch(t *testing.T) {
	pool := vLivePool(t)
	pg := &PostgresConfig{dbpool: pool}

	cases := map[string]func(*EventStruct){
		"message>varchar(5000)":    func(e *EventStruct) { e.Output = strings.Repeat("A", 5001) },
		"uuid not a uuid":          func(e *EventStruct) { e.Uuid = "not-a-uuid" },
		"hostname>varchar(255)":    func(e *EventStruct) { e.Hostname = strings.Repeat("h", 256) },
		"rule>varchar(80)":         func(e *EventStruct) { e.Rule = strings.Repeat("r", 81) },
		"priority>varchar(30)":     func(e *EventStruct) { e.Priority = strings.Repeat("p", 31) },
		"source>varchar(50)":       func(e *EventStruct) { e.Source = strings.Repeat("s", 51) },
		"tags>varchar(126)":        func(e *EventStruct) { e.Tags = json.RawMessage(`"` + strings.Repeat("t", 200) + `"`) },
		"project>varchar(50) [id]": func(e *EventStruct) {
			// Attacker-shaped identity the parseClusterId regex accepts; project parses to 53 chars.
			id := "shoot--p--" + strings.Repeat("a", 50) + "--x-123e4567-e89b-12d3-a456-426614174000-garden-dev"
			e.OutputFields["cluster_id"] = json.RawMessage(`"` + id + `"`)
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			vLiveTruncate(t, pool)
			bad := vLiveEvent()
			mutate(&bad)
			batch := []EventStruct{vLiveEvent(), bad, vLiveEvent()}

			err := pg.Insert(batch)
			if err == nil {
				t.Fatalf("expected the poisoned batch to be rejected")
			}
			n := vLiveCount(t, pool)
			if n != 0 {
				t.Fatalf("ATOMICITY VIOLATED: %d rows survived after a batch error (err=%v)", n, err)
			}
			t.Logf("%-26s -> Insert error %q ; rows persisted = 0 (valid siblings rolled back)", name, err.Error())
		})
	}
}

// The Go-side check aborts BEFORE CopyFrom: the error text is the local size
// error, not "failed to insert events", and zero rows persist.
func TestValidatorLive_SizeCheckAbortsBeforeCopyFrom(t *testing.T) {
	pool := vLivePool(t)
	pg := &PostgresConfig{dbpool: pool}
	vLiveTruncate(t, pool)

	bad := vLiveEvent()
	bad.OutputFields["pad"] = json.RawMessage(`"` + strings.Repeat("B", 60000) + `"`)
	err := pg.Insert([]EventStruct{vLiveEvent(), bad, vLiveEvent()})
	if err == nil {
		t.Fatal("expected rejection")
	}
	if strings.Contains(err.Error(), "failed to insert events") {
		t.Fatalf("expected pre-CopyFrom abort, got a DB error: %v", err)
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := vLiveCount(t, pool); n != 0 {
		t.Fatalf("expected 0 rows, got %d", n)
	}
	t.Logf("SIZE CHECK: Insert returned %q before CopyFrom ; rows persisted = 0", err.Error())
}
