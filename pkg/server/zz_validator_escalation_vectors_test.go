// SPDX-License-Identifier: Apache-2.0
//
// VALIDATOR-ONLY tests (post-escalation re-validation, hyp #20):
//   Test 1  claim 2 -- is the "local-fail" poison really AS destructive as the
//           DB-reaching one, across repeated trials? Uses the drainer's own
//           "Error inserting N event(s)" log lines as a batch-size oracle.
//   Test 2  claim 3 -- is the cross-tenant HTTP 500 under a stalled inserter
//           specific to the POISON, or does ANY same-rate flood (valid events)
//           produce it? (i.e. is the 500 a poison effect or generic backpressure?)
//
// Run:
//   ESC_PG_DSN='postgres://postgres:escalator@127.0.0.1:5455/falco' \
//     go test -v -count=1 -timeout 600s -run TestValidatorEscalationVector ./pkg/server/
package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestValidatorEscalationVector_MultiTrial(t *testing.T) {
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

	vectors := []struct {
		name string
		body []byte
	}{
		{"db_reaching_output_gt_5000", escBody(attacker, strings.Repeat("A", 5001), 0)},
		{"local_fail_pad_gt_50KiB", escBody(attacker, "esc valid telemetry", 60000)},
		{"control_valid", escBody(attacker, "esc valid telemetry", 0)},
	}

	const attackerRate = 1600.0
	const victimRatePerTenant = 100.0
	const dur = 3 * time.Second
	const trials = 4

	for _, v := range vectors {
		v := v
		for i := 1; i <= trials; i++ {
			i := i
			t.Run(v.name+"_trial"+string(rune('0'+i)), func(t *testing.T) {
				escTruncate(t, pool)
				buf := &vSafeBuf{}
				log.SetOutput(buf)
				defer log.SetOutput(io.Discard)

				s := escNewServer(pg)
				mux := http.NewServeMux()
				mux.HandleFunc("/ingestor/api/v1/push", newHandlePush(a, s))
				srv := httptest.NewServer(mux)
				defer srv.Close()
				client := escClient()

				ctx, cancel := context.WithTimeout(context.Background(), dur)
				res := escRun(t, ctx, client, srv.URL, key, victims, victimRatePerTenant, attacker, attackerRate, v.body)
				cancel()
				backlog := len(s.eventChannel)
				drained, drainDur := vWaitDrain(s, 60*time.Second)

				persisted := escVictimPersisted(t, pool, victims)
				silent := res.victimAccepted - int64(persisted)
				if silent < 0 {
					silent = 0
				}
				lossPct := 0.0
				if res.victimAccepted > 0 {
					lossPct = 100 * float64(silent) / float64(res.victimAccepted)
				}
				nb, _, avg := vParseBatches(buf.String())
				t.Logf("%-28s trial%d | victim accepted=%d persisted=%d LOSS=%.1f%% | failed_batches=%d avg_batch=%.1f backlog=%d drained=%v %s",
					v.name, i, res.victimAccepted, persisted, lossPct, nb, avg, backlog, drained, drainDur.Round(time.Millisecond))
			})
		}
	}
}

// Claim 3: does a VALID-event flood (no poison at all) from tenant A also make
// tenant B's push return 500 while the shared inserter is stalled? If yes, the
// 500 is generic back-pressure, not a property of the poison.
func TestValidatorEscalationVector_BackpressureValidFlood(t *testing.T) {
	dsn := escDSN(t)
	pool := escCountPool(t, dsn)
	pg := escPGConfig(t)
	a, key := escSetupAuth(t)

	attacker := "shoot--attacker--shootx-99999999-9999-9999-9999-999999999999-garden-dev"
	victim := "shoot--victim-a--shoot1-11111111-1111-1111-1111-111111111111-garden-dev"

	for _, flavour := range []struct {
		name string
		body []byte
	}{
		{"poison_flood", escBody(attacker, strings.Repeat("A", 5001), 0)},
		{"valid_flood", escBody(attacker, "esc valid attacker telemetry", 0)},
	} {
		flavour := flavour
		t.Run(flavour.name, func(t *testing.T) {
			ctx := context.Background()
			lk, err := pool.Acquire(ctx)
			if err != nil {
				t.Fatalf("acquire lock conn: %v", err)
			}
			if _, err := lk.Exec(ctx, "BEGIN"); err != nil {
				t.Fatalf("begin: %v", err)
			}
			if _, err := lk.Exec(ctx, "LOCK TABLE falco_events IN ACCESS EXCLUSIVE MODE"); err != nil {
				t.Fatalf("lock: %v", err)
			}

			s := escNewServer(pg)
			mux := http.NewServeMux()
			mux.HandleFunc("/ingestor/api/v1/push", newHandlePush(a, s))
			srv := httptest.NewServer(mux)
			client := escClient()

			stop := make(chan struct{})
			atok := escToken(t, key, attacker)
			for i := 0; i < 16; i++ {
				go func() {
					for {
						select {
						case <-stop:
							return
						default:
						}
						escPost(client, srv.URL, atok, flavour.body)
					}
				}()
			}
			time.Sleep(2500 * time.Millisecond)
			occ := len(s.eventChannel)

			vtok := escToken(t, key, victim)
			start := time.Now()
			code := escPost(client, srv.URL, vtok, escBody(victim, "valid victim telemetry", 0))
			elapsed := time.Since(start)
			t.Logf("flood=%s | channel occupancy=%d/5000 | victim-B status=%d after %s",
				flavour.name, occ, code, elapsed.Round(time.Millisecond))

			close(stop)
			time.Sleep(300 * time.Millisecond)
			if _, err := lk.Exec(ctx, "ROLLBACK"); err != nil {
				t.Logf("rollback: %v", err)
			}
			lk.Release()
			srv.Close()
			escWaitDrain(s, 20*time.Second)
		})
	}
}
