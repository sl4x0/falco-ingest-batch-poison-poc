// SPDX-License-Identifier: Apache-2.0
//
// VALIDATOR-ONLY control test (post-escalation re-validation, hyp #20).
//
// The escalator's sweep has ONE control: attacker rate 0. That control cannot
// separate "the poison discarded the victims" from "the harness/DB simply
// saturated at high load" -- both look like accepted-but-not-persisted.
//
// This test runs the SAME total load with three attacker variants:
//   B. attacker stream is VALID  (same 6400/s, same tokens, short output)
//   C. attacker stream is POISON (same 6400/s, message>varchar(5000))
// plus a victim-only throughput ladder (0..13600 ev/s, no attacker at all) to
// measure the harness's own valid-event ceiling.
//
// If the harness can persist 6800 valid events/s (arms D/E/F and B), then the
// loss in C is caused by the poison. If it cannot, the "blackout" is a harness
// artifact and the escalation is unsupported.
//
// It also collects the drainer's own real log lines ("Error inserting N
// event(s)") as a batch-size oracle, to test claim 2's drain-window mechanism.
//
// Run:
//   ESC_PG_DSN='postgres://postgres:escalator@127.0.0.1:5455/falco' \
//     go test -v -count=1 -timeout 600s -run TestValidatorEscalation ./pkg/server/
package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

// vSafeBuf is a concurrency-safe sink for logrus output (the drainer goroutine
// and the test goroutine both touch it).
type vSafeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *vSafeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *vSafeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

var vBatchRe = regexp.MustCompile(`Error inserting (\d+) event\(s\)`)

// vParseBatches returns (numBatches, totalEventsInFailedBatches, avgSize).
func vParseBatches(logs string) (int, int, float64) {
	ms := vBatchRe.FindAllStringSubmatch(logs, -1)
	n, tot := 0, 0
	for _, m := range ms {
		v, _ := strconv.Atoi(m[1])
		n++
		tot += v
	}
	avg := 0.0
	if n > 0 {
		avg = float64(tot) / float64(n)
	}
	return n, tot, avg
}

// vWaitDrain waits until the shared channel is empty (or max elapses); returns
// whether it fully drained and how long it took.
func vWaitDrain(s *Server, max time.Duration) (bool, time.Duration) {
	start := time.Now()
	deadline := start.Add(max)
	for time.Now().Before(deadline) {
		if len(s.eventChannel) == 0 {
			time.Sleep(200 * time.Millisecond)
			if len(s.eventChannel) == 0 {
				return true, time.Since(start)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false, time.Since(start)
}

func vTotalRows(t *testing.T, dsn string) int {
	t.Helper()
	pool := escCountPool(t, dsn)
	var n int
	if err := pool.QueryRow(context.Background(), "select count(*) from falco_events").Scan(&n); err != nil {
		t.Fatalf("count all: %v", err)
	}
	return n
}

func TestValidatorEscalation_SaturationVsPoison(t *testing.T) {
	dsn := escDSN(t)
	pool := escCountPool(t, dsn)
	pg := escPGConfig(t)
	a, key := escSetupAuth(t)

	victims := []string{
		"shoot--victim-a--shoot1-11111111-1111-1111-1111-111111111111-garden-dev",
		"shoot--victim-b--shoot2-22222222-2222-2222-2222-222222222222-garden-dev",
		"shoot--victim-c--shoot3-33333333-3333-3333-3333-333333333333-garden-dev",
		"shoot--victim-d--shoot4-44444444-4444-4444-4444-444444444444-garden-dev",
	}
	attacker := "shoot--attacker--shootx-99999999-9999-9999-9999-999999999999-garden-dev"

	const dur = 3 * time.Second

	type arm struct {
		name         string
		attackerRate float64
		attackerBody []byte
		victimRate   float64 // per tenant
	}
	arms := []arm{
		{"A_control_victim_only_400ps", 0, nil, 100},
		{"B_valid_attacker_6400ps", 6400, escBody(attacker, "esc valid attacker telemetry", 0), 100},
		{"C_poison_attacker_6400ps", 6400, escBody(attacker, strings.Repeat("A", 5001), 0), 100},
		{"D_victim_only_2000ps", 0, nil, 500},
		{"E_victim_only_6800ps", 0, nil, 1700},
		{"F_victim_only_13600ps", 0, nil, 3400},
	}

	for _, ar := range arms {
		ar := ar
		t.Run(ar.name, func(t *testing.T) {
			escTruncate(t, pool)
			buf := &vSafeBuf{}
			log.SetOutput(buf)
			defer log.SetOutput(io.Discard)

			s := escNewServer(pg)
			mux := http.NewServeMux()
			mux.HandleFunc("/ingestor/api/v1/push", newHandlePush(a, s))
			srv := httptest.NewServer(mux)
			client := escClient()

			ctx, cancel := context.WithTimeout(context.Background(), dur)
			res := escRun(t, ctx, client, srv.URL, key, victims, ar.victimRate, attacker, ar.attackerRate, ar.attackerBody)
			cancel()

			backlogAtEnd := len(s.eventChannel)
			drained, drainDur := vWaitDrain(s, 60*time.Second)

			byProject := escCountByProject(t, pool)
			persisted := escVictimPersisted(t, pool, victims)
			attackerPersisted := byProject[escProject(attacker)]
			total := vTotalRows(t, dsn)

			silent := res.victimAccepted - int64(persisted)
			if silent < 0 {
				silent = 0
			}
			lossPct := 0.0
			if res.victimAccepted > 0 {
				lossPct = 100 * float64(silent) / float64(res.victimAccepted)
			}
			nb, tot, avg := vParseBatches(buf.String())
			achAtt := float64(res.attackerAttempted) / dur.Seconds()
			achVic := float64(res.victimAttempted) / dur.Seconds()

			t.Logf("arm=%s attacker_target=%.0f/s achieved=%.1f/s accepted=%d | victim_achieved=%.1f/s attempted=%d accepted=%d rejected=%d",
				ar.name, ar.attackerRate, achAtt, res.attackerAccepted, achVic, res.victimAttempted, res.victimAccepted, res.victimRejected)
			t.Logf("   victim persisted=%d  SILENT LOSS=%d (%.2f%%)  | attacker_rows=%d  TOTAL_rows=%d",
				persisted, silent, lossPct, attackerPersisted, total)
			t.Logf("   drain: backlog_at_end=%d fully_drained=%v drain_time=%s | failed_batches=%d events_in_failed_batches=%d avg_batch=%.1f",
				backlogAtEnd, drained, drainDur.Round(time.Millisecond), nb, tot, avg)
			srv.Close()
		})
	}
}
