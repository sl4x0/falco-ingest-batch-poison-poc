// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// PoC harness for falco-event-ingestor. This file is NOT part of upstream; it is
// a reproducer. It lives in-package because parseClusterId is unexported and the
// dbpool field has to be substituted.
package postgres

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pocIdentity = "shoot--victimproj--victimcluster-123e4567-e89b-12d3-a456-426614174000-garden-dev"

func pocEvent() EventStruct {
	return EventStruct{
		Uuid:         "123e4567-e89b-12d3-a456-426614174000",
		Output:       "poc output",
		Priority:     "Notice",
		Rule:         "poc rule",
		Time:         time.Now().UTC(),
		OutputFields: map[string]json.RawMessage{"cluster_id": json.RawMessage(`"` + pocIdentity + `"`)},
		Source:       "syscall",
		Tags:         json.RawMessage(`["container"]`),
		Hostname:     "falco-abcde",
	}
}

// pocDeadPool returns a real *pgxpool.Pool that can never connect (port 1), so a
// batch that actually reaches CopyFrom fails with a dial/connect error instead of
// touching any database. That difference in error text is used to prove WHERE the
// insert aborted.
func pocDeadPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("host=127.0.0.1 port=1 user=poc password=poc dbname=poc connect_timeout=1")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// PoC: a single store-fatal event makes Insert return before CopyFrom, so every
// other event in the same batch (other tenants included) is discarded.
func TestPoC_InsertAbortsWholeBatchBeforeCopyFrom(t *testing.T) {
	pg := &PostgresConfig{dbpool: pocDeadPool(t)}

	poison := pocEvent()
	poison.OutputFields["pad"] = json.RawMessage(`"` + strings.Repeat("B", 60000) + `"`) // > MAX_JSONB_SIZE

	err := pg.Insert([]EventStruct{pocEvent(), poison, pocEvent()})
	if err == nil {
		t.Fatal("expected the poisoned batch to be rejected")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected the pre-DB size error, got: %v", err)
	}
	t.Logf("POISONED batch (victim, attacker-poison, victim) aborted BEFORE any DB round-trip: %v", err)
	t.Logf("-> the whole batch is lost; CopyFrom is atomic and is never even attempted")

	// Control: the very same batch without the poison event does reach the DB layer.
	cerr := pg.Insert([]EventStruct{pocEvent(), pocEvent(), pocEvent()})
	if cerr == nil {
		t.Fatal("control: expected a DB error from the dead pool, batch reported success")
	}
	if !strings.Contains(cerr.Error(), "failed to insert events") {
		t.Fatalf("control: expected CopyFrom to be reached, got: %v", cerr)
	}
	t.Logf("CONTROL batch (victim, victim, victim) reached CopyFrom: %v", cerr)
}

// PoC: parseClusterId accepts attacker-shaped identities that overflow the
// varchar(50) project/cluster/landscape columns, a second way to make CopyFrom
// fail and drop the whole batch (PostgreSQL 22001 value too long).
func TestPoC_ParsedProjectCanOverflowVarchar50(t *testing.T) {
	// A shoot namespace is shoot--<project>--<shoot>; a shoot name containing "--"
	// makes the greedy `([\w-]+)` project group swallow most of the shoot name.
	identity := "shoot--p--" + strings.Repeat("a", 50) + "--x-" + "123e4567-e89b-12d3-a456-426614174000-garden-dev"
	ev := pocEvent()
	ev.OutputFields["cluster_id"] = json.RawMessage(`"` + identity + `"`)

	ci, err := parseClusterId(ev)
	if err != nil {
		t.Fatalf("crafted identity was rejected by the regex: %v", err)
	}
	t.Logf("parsed from a 63-char namespace: project=%q (len=%d) cluster=%q (len=%d) landscape=%q (len=%d)",
		ci.project, len(ci.project), ci.cluster, len(ci.cluster), ci.landscape, len(ci.landscape))
	if len(ci.project) <= 50 {
		t.Fatalf("expected parsed project to exceed the varchar(50) column, got %d chars", len(ci.project))
	}
	t.Logf("-> project exceeds falco_events.project varchar(50); CopyFrom fails 22001 and the batch is dropped")
}
