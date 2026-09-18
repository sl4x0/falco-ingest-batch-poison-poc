// SPDX-License-Identifier: Apache-2.0
//
// ESCALATOR-ONLY tests (hyp #20, falco-event-ingestor @ a70f6443).
//
// These push the validator-confirmed per-batch drop to its ceiling: is it one
// batch, or can ONE tenant suppress a LARGE FRACTION of ALL tenants' telemetry
// (landscape-wide security-monitoring blackout)? They drive the REAL
// newHandlePush over HTTP with REAL RS256 tenant tokens, the REAL async drainer
// (readEventsFromChannel), and a REAL PostgreSQL 16 carrying the exact upstream
// DDL - no sentinels.
//
// Run:
//   ESC_PG_DSN='postgres://postgres:escalator@127.0.0.1:5455/falco' \
//     go test -v -count=1 -timeout 600s -run 'Escalator' ./pkg/server/
package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gardener/falco-event-ingestor/pkg/auth"
	"github.com/gardener/falco-event-ingestor/pkg/postgres"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// escQuiet drops the ingestor's own logrus output so the test result lines are
// not buried by the expected per-poisoned-batch error lines.
func escQuiet() {
	log.SetOutput(io.Discard)
	stdlog.SetOutput(io.Discard) // net/http's recovered-panic stack traces
}

// ---------------------------------------------------------------------------
// harness plumbing
// ---------------------------------------------------------------------------

func escEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func escDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("ESC_PG_DSN")
	if dsn == "" {
		t.Skip("ESC_PG_DSN not set")
	}
	return dsn
}

func escCountPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
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

// escPGConfig builds a *postgres.PostgresConfig with a REAL pool via the exported
// constructor (the pool field is unexported, so this is the only cross-package way).
func escPGConfig(t *testing.T) *postgres.PostgresConfig {
	t.Helper()
	host := escEnv("ESC_PG_HOST", "127.0.0.1")
	port := 0
	fmt.Sscanf(escEnv("ESC_PG_PORT", "5455"), "%d", &port)
	return postgres.NewPostgresConfig(
		escEnv("ESC_PG_USER", "postgres"),
		escEnv("ESC_PG_PASS", "escalator"),
		host, port,
		escEnv("ESC_PG_DB", "falco"),
		7,
	)
}

func escTruncate(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), "truncate falco_events"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// escCountByProject returns rows persisted per `project`.
func escCountByProject(t *testing.T, pool *pgxpool.Pool) map[string]int {
	t.Helper()
	rows, err := pool.Query(context.Background(), "select project, count(*) from falco_events group by project")
	if err != nil {
		t.Fatalf("count query: %v", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var p string
		var n int
		if err := rows.Scan(&p, &n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[p] = n
	}
	return out
}

func escProject(clusterID string) string {
	// shoot--<project>--<cluster>-<uid>-<landscape>
	parts := strings.Split(clusterID, "--")
	if len(parts) < 2 {
		return clusterID
	}
	return parts[1]
}

// --- auth ---

func escKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	return k
}

// escSetupAuth writes a keys.yaml for the ingestor and returns the verifier plus
// the signing key (all tenants' tokens are signed by the extension's one key,
// exactly as the real deployment signs every shoot's ingest JWT).
func escSetupAuth(t *testing.T) (*auth.Auth, *rsa.PrivateKey) {
	t.Helper()
	key := escKey(t)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	block := func() string {
		lines := strings.Split(strings.TrimSpace(pub), "\n")
		for i, l := range lines {
			lines[i] = "    " + l
		}
		return "  publicKey: |\n" + strings.Join(lines, "\n")
	}
	yml := "key_1:\n" + block() + "\n  created: 2024-01-01T00:00:00Z\n" +
		"key_2:\n" + block() + "\n  created: 2024-01-02T00:00:00Z\n"
	path := filepath.Join(t.TempDir(), "keys.yaml")
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatalf("write keys: %v", err)
	}
	a := auth.NewAuth()
	if err := a.ReadKeysFile(path); err != nil {
		t.Fatalf("ReadKeysFile: %v", err)
	}
	return a, key
}

func escToken(t *testing.T, key *rsa.PrivateKey, clusterID string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"gardener-falco": map[string]string{"cluster-identity": clusterID},
		"iss":            "urn:gardener:gardener-falco-extension",
		"aud":            "falco-db",
		"exp":            time.Now().Add(time.Hour).Unix(),
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// --- events / server / client ---

func escBody(clusterID, output string, pad int) []byte {
	fields := map[string]interface{}{"cluster_id": clusterID}
	if pad > 0 {
		fields["pad"] = strings.Repeat("B", pad)
	}
	ev := map[string]interface{}{
		"uuid":          "123e4567-e89b-12d3-a456-426614174000",
		"output":        output,
		"priority":      "Notice",
		"rule":          "esc rule",
		"time":          time.Now().UTC().Format(time.RFC3339Nano),
		"output_fields": fields,
		"source":        "syscall",
		"tags":          []string{"container"},
		"hostname":      "falco-abcde",
	}
	b, err := json.Marshal(ev)
	if err != nil {
		panic(err)
	}
	return b
}

// escNewServer mirrors NewServer's effective config (channel cap 5000, the two
// no-op rate limiters) but without binding real ports, and starts the REAL
// async drainer.
func escNewServer(pg *postgres.PostgresConfig) *Server {
	// Byte-for-byte the same limiter configuration as the real NewServer
	// (server.go:51-57) and the real values.yaml deployment default
	// (clusterDailyEventLimit: 100000000000): both limiters are effective no-ops.
	const clusterDailyEventLimit = 100000000000
	generalLimiter := rate.NewLimiter(rate.Limit(clusterDailyEventLimit), clusterDailyEventLimit)
	s := &Server{
		eventChannel:   make(chan postgres.EventStruct, 5000),
		postgres:       pg,
		clusterLimits:  map[string]*clusterLimiter{},
		generalLimiter: generalLimiter,
		clusterLimit:   rate.Every(24 * time.Hour / time.Duration(clusterDailyEventLimit)),
		clusterBurst:   clusterDailyEventLimit / 3,
	}
	go s.readEventsFromChannel()
	return s
}

func escClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        512,
			MaxIdleConnsPerHost: 512,
			DisableCompression:  true,
		},
		Timeout: 30 * time.Second,
	}
}

func escPost(client *http.Client, url, token string, body []byte) int {
	req, err := http.NewRequest("POST", url+"/ingestor/api/v1/push", bytes.NewReader(body))
	if err != nil {
		return -1
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return -1
	}
	resp.Body.Close()
	return resp.StatusCode
}

type escResult struct {
	victimAttempted   int64
	victimAccepted    int64 // HTTP 200 (enqueued)
	victimRejected    int64 // non-200 (e.g. 500 back-pressure, 429)
	attackerAttempted int64
	attackerAccepted  int64
}

// escRun drives the real HTTP boundary concurrently for `dur`: one paced worker
// per victim tenant (valid events) and N unpaced/paced attacker workers (poison).
func escRun(t *testing.T, ctx context.Context, client *http.Client, url string, key *rsa.PrivateKey,
	victimIDs []string, victimRatePerTenant float64,
	attackerID string, attackerRate float64, attackerBody []byte) escResult {
	t.Helper()

	var victimAttempted, victimAccepted, victimRejected int64
	var attackerAttempted, attackerAccepted int64
	var wg sync.WaitGroup

	for _, vid := range victimIDs {
		tok := escToken(t, key, vid)
		body := escBody(vid, "esc valid telemetry", 0)
		burst := int(victimRatePerTenant/5) + 2
		lim := rate.NewLimiter(rate.Limit(victimRatePerTenant), burst)
		wg.Add(1)
		go func(tok string, body []byte, lim *rate.Limiter) {
			defer wg.Done()
			for {
				if err := lim.Wait(ctx); err != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				default:
				}
				code := escPost(client, url, tok, body)
				atomic.AddInt64(&victimAttempted, 1)
				if code == http.StatusOK {
					atomic.AddInt64(&victimAccepted, 1)
				} else {
					atomic.AddInt64(&victimRejected, 1)
				}
			}
		}(tok, body, lim)
	}

	if attackerRate > 0 && attackerBody != nil {
		atok := escToken(t, key, attackerID)
		const nw = 8
		per := attackerRate / float64(nw)
		for i := 0; i < nw; i++ {
			burst := int(per/5) + 2
			lim := rate.NewLimiter(rate.Limit(per), burst)
			wg.Add(1)
			go func(lim *rate.Limiter) {
				defer wg.Done()
				for {
					if err := lim.Wait(ctx); err != nil {
						return
					}
					select {
					case <-ctx.Done():
						return
					default:
					}
					code := escPost(client, url, atok, attackerBody)
					atomic.AddInt64(&attackerAttempted, 1)
					if code == http.StatusOK {
						atomic.AddInt64(&attackerAccepted, 1)
					}
				}
			}(lim)
		}
	}

	wg.Wait()
	return escResult{victimAttempted, victimAccepted, victimRejected, attackerAttempted, attackerAccepted}
}

// escWaitDrain waits until the shared channel is quiet, then a settle period so
// the final in-flight Insert can finish.
func escWaitDrain(s *Server, max time.Duration) {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if len(s.eventChannel) == 0 {
			time.Sleep(200 * time.Millisecond)
			if len(s.eventChannel) == 0 {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func escVictimPersisted(t *testing.T, pool *pgxpool.Pool, victimIDs []string) int {
	byProject := escCountByProject(t, pool)
	total := 0
	for _, v := range victimIDs {
		total += byProject[escProject(v)]
	}
	return total
}

// ---------------------------------------------------------------------------
// TEST 1 (highest value): sustained / landscape-scale suppression.
//
// One tenant (the attacker) floods the SHARED channel with store-fatal events
// that pass every Go-side check and are only rejected by PostgreSQL inside
// CopyFrom. Because CopyFrom is atomic, every batch that contains >=1 poison is
// rolled back entirely, dropping the victim events that share it. The question
// is not "can one batch be poisoned" (the validator proved that) but "what
// poison rate is needed to poison EVERY batch, i.e. suppress the whole
// landscape's telemetry".
// ---------------------------------------------------------------------------
func TestEscalator_PoisonRateSweep(t *testing.T) {
	escQuiet()
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

	// Store-fatal but passes every Go-side check: `output` 5001 chars only
	// violates message varchar(5000) inside PostgreSQL -> the batch does a FULL
	// DB round trip and is rejected by COPY, so the drain window stays large and
	// batches keep accumulating victims.
	poison := escBody(attacker, strings.Repeat("A", 5001), 0)

	const victimRatePerTenant = 100.0 // 400 events/s of victim telemetry across the landscape
	const dur = 3 * time.Second

	points := []struct {
		name         string
		attackerRate float64
	}{
		{"00_no_attacker_CONTROL", 0},
		{"01_attacker_1x_400ps", 400},
		{"02_attacker_4x_1600ps", 1600},
		{"03_attacker_8x_3200ps", 3200},
		{"04_attacker_16x_6400ps", 6400},
		{"05_attacker_32x_12800ps", 12800},
	}

	for _, p := range points {
		p := p
		t.Run(p.name, func(t *testing.T) {
			escTruncate(t, pool)
			s := escNewServer(pg)
			mux := http.NewServeMux()
			mux.HandleFunc("/ingestor/api/v1/push", newHandlePush(a, s))
			srv := httptest.NewServer(mux)
			defer srv.Close()
			client := escClient()

			ctx, cancel := context.WithTimeout(context.Background(), dur)
			res := escRun(t, ctx, client, srv.URL, key, victims, victimRatePerTenant, attacker, p.attackerRate, poison)
			cancel()
			escWaitDrain(s, 8*time.Second)

			persisted := escVictimPersisted(t, pool, victims)
			silent := res.victimAccepted - int64(persisted)
			if silent < 0 {
				silent = 0
			}
			lossPct := 0.0
			if res.victimAccepted > 0 {
				lossPct = 100 * float64(silent) / float64(res.victimAccepted)
			}
			achAtt := float64(res.attackerAttempted) / dur.Seconds()
			achVic := float64(res.victimAttempted) / dur.Seconds()

			byProject := escCountByProject(t, pool)
			perTenant := make([]string, 0, len(victims))
			for _, v := range victims {
				perTenant = append(perTenant, fmt.Sprintf("%s=%d", escProject(v), byProject[escProject(v)]))
			}
			t.Logf("attacker target=%6.0f/s achieved=%7.1f/s  | victims achieved=%6.1f/s over %s",
				p.attackerRate, achAtt, achVic, dur)
			t.Logf("victims: attempted=%d accepted(200)=%d rejected(non-200)=%d persisted=%d  [per-tenant: %s]",
				res.victimAttempted, res.victimAccepted, res.victimRejected, persisted, strings.Join(perTenant, " "))
			t.Logf("=> SILENT LOSS (accepted-but-not-stored) = %d  (%.1f%% of accepted victim events)", silent, lossPct)
			t.Logf("expected-loss-model: 1-exp(-attacker_rate*D) with fitted D=(batch window); every victim event co-batched with >=1 poison is rolled back")

			if p.attackerRate == 0 {
				if lossPct > 10 {
					t.Errorf("CONTROL broken: %.1f%% of victim events were lost with no attacker (harness/DB problem)", lossPct)
				}
				t.Logf("CONTROL: %d/%d victim events persisted; harness sanity check pass.", persisted, res.victimAccepted)
				return
			}
			if lossPct <= 10 {
				t.Errorf("expected the flood to suppress victim telemetry, got only %.1f%%", lossPct)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TEST 2: which poison vector is the catastrophic one?
//
// A *DB-reaching* poison (message>varchar(5000)) keeps the drain window at a full
// DB round trip, so batches stay large and every poisoned batch takes victims
// with it. A *local-fail* poison (output_fields>50KiB, rejected in Go before any
// round trip) collapses the drain window to microseconds, so batches shrink to
// ~1 event and the collateral loss is bounded. This is the falsification test for
// the naive "any poison suppresses everything" claim.
// ---------------------------------------------------------------------------
func TestEscalator_PoisonVectorComparison(t *testing.T) {
	escQuiet()
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
		{"db_reaching_message_gt_5000", escBody(attacker, strings.Repeat("A", 5001), 0)},
		{"local_fail_output_fields_gt_50KiB", escBody(attacker, "esc valid telemetry", 60000)},
	}

	const victimRatePerTenant = 100.0
	const attackerRate = 1600.0
	const dur = 3 * time.Second

	for _, v := range vectors {
		v := v
		t.Run(v.name, func(t *testing.T) {
			escTruncate(t, pool)
			s := escNewServer(pg)
			mux := http.NewServeMux()
			mux.HandleFunc("/ingestor/api/v1/push", newHandlePush(a, s))
			srv := httptest.NewServer(mux)
			defer srv.Close()
			client := escClient()

			ctx, cancel := context.WithTimeout(context.Background(), dur)
			res := escRun(t, ctx, client, srv.URL, key, victims, victimRatePerTenant, attacker, attackerRate, v.body)
			cancel()
			escWaitDrain(s, 8*time.Second)

			persisted := escVictimPersisted(t, pool, victims)
			silent := res.victimAccepted - int64(persisted)
			if silent < 0 {
				silent = 0
			}
			lossPct := 0.0
			if res.victimAccepted > 0 {
				lossPct = 100 * float64(silent) / float64(res.victimAccepted)
			}
			t.Logf("vector=%s | victims accepted=%d persisted=%d | SILENT LOSS=%d (%.1f%%)",
				v.name, res.victimAccepted, persisted, silent, lossPct)
		})
	}
}

// ---------------------------------------------------------------------------
// TEST 3: malformed Bearer token - reachability and cost.
//
// VerifyToken indexes parts[2] of strings.Split(token, ".") with no length check,
// BEFORE any signature verification. The panic is therefore reachable with NO
// valid token at all (unauthenticated). net/http recovers per connection, so this
// measures whether it is merely per-request noise or an amplification vector.
// ---------------------------------------------------------------------------
func TestEscalator_MalformedTokenFlood(t *testing.T) {
	escQuiet()
	s := &Server{
		eventChannel:   make(chan postgres.EventStruct, 64),
		postgres:       &postgres.PostgresConfig{},
		clusterLimits:  map[string]*clusterLimiter{},
		generalLimiter: rate.NewLimiter(rate.Inf, 1<<30),
		clusterLimit:   rate.Inf,
		clusterBurst:   1 << 30,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ingestor/api/v1/push", newHandlePush(auth.NewAuth(), s))
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := escClient()

	const n = 1000
	const conc = 32

	// Baseline: no Authorization header -> 401, no panic path.
	base := escFlood(client, srv.URL, n, conc, func(i int) string { return "" })
	// Attack: syntactically invalid bearer tokens -> panic path (pre-signature).
	atk := escFlood(client, srv.URL, n, conc, func(i int) string { return "Bearer x" })
	// Attack 2: two-segment token -> parts[2] index panic.
	atk2 := escFlood(client, srv.URL, n, conc, func(i int) string { return "Bearer a.b" })

	t.Logf("baseline (no token, 401 path):   %d reqs in %s  (%.0f req/s)", n, base.Round(time.Millisecond), float64(n)/base.Seconds())
	t.Logf("attack   (Bearer x, panic path): %d reqs in %s  (%.0f req/s)", n, atk.Round(time.Millisecond), float64(n)/atk.Seconds())
	t.Logf("attack   (Bearer a.b, panic):    %d reqs in %s  (%.0f req/s)", n, atk2.Round(time.Millisecond), float64(n)/atk2.Seconds())

	resp, err := client.Get(srv.URL + "/ok")
	if err != nil {
		t.Fatalf("server died after %d panics: %v", n*2, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("server unhealthy after panics: %d", resp.StatusCode)
	}
	t.Logf("server still serving after %d recovered handler panics (each emits a full goroutine stack trace to the log)", n*2)
}

func escFlood(client *http.Client, base string, n, conc int, hdr func(int) string) time.Duration {
	var wg sync.WaitGroup
	jobs := make(chan int)
	start := time.Now()
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				req, err := http.NewRequest("POST", base+"/ingestor/api/v1/push", strings.NewReader("{}"))
				if err != nil {
					continue
				}
				if h := hdr(i); h != "" {
					req.Header.Set("Authorization", h)
				}
				resp, err := client.Do(req)
				if err == nil && resp != nil {
					resp.Body.Close()
				}
			}
		}()
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return time.Since(start)
}

// ---------------------------------------------------------------------------
// TEST 4: reproducibility of the near-total blackout at 16x attacker rate.
// ---------------------------------------------------------------------------
func TestEscalator_BlackoutReproducibility(t *testing.T) {
	escQuiet()
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
	poison := escBody(attacker, strings.Repeat("A", 5001), 0)

	const attackerRate = 6400.0
	const victimRatePerTenant = 100.0
	const dur = 2 * time.Second

	for i := 1; i <= 3; i++ {
		escTruncate(t, pool)
		s := escNewServer(pg)
		mux := http.NewServeMux()
		mux.HandleFunc("/ingestor/api/v1/push", newHandlePush(a, s))
		srv := httptest.NewServer(mux)
		client := escClient()

		ctx, cancel := context.WithTimeout(context.Background(), dur)
		res := escRun(t, ctx, client, srv.URL, key, victims, victimRatePerTenant, attacker, attackerRate, poison)
		cancel()
		escWaitDrain(s, 8*time.Second)
		persisted := escVictimPersisted(t, pool, victims)
		silent := res.victimAccepted - int64(persisted)
		if silent < 0 {
			silent = 0
		}
		lossPct := 100 * float64(silent) / float64(res.victimAccepted)
		t.Logf("run %d/3: victims attempted=%d accepted=%d rejected=%d persisted=%d -> SILENT LOSS=%d (%.2f%%)",
			i, res.victimAttempted, res.victimAccepted, res.victimRejected, persisted, silent, lossPct)
		srv.Close()
	}
}

// ---------------------------------------------------------------------------
// TEST 5: back-pressure coupling - one tenant's flood + a stalled shared
// inserter turns into HTTP 500 for a DIFFERENT tenant.
//
// The channel is 5000 slots and writeEventToChannel waits only 5s. The reader
// goroutine is single and synchronous, so if its Insert stalls (here: an
// external ACCESS EXCLUSIVE table lock standing in for DB contention), the
// channel fills and every tenant's push times out with 500. This probes whether
// the ingest API's failure mode is per-tenant or global.
// ---------------------------------------------------------------------------
func TestEscalator_BackpressureCrossTenant500(t *testing.T) {
	escQuiet()
	dsn := escDSN(t)
	pool := escCountPool(t, dsn)
	pg := escPGConfig(t)
	a, key := escSetupAuth(t)

	attacker := "shoot--attacker--shootx-99999999-9999-9999-9999-999999999999-garden-dev"
	victim := "shoot--victim-a--shoot1-11111111-1111-1111-1111-111111111111-garden-dev"
	poison := escBody(attacker, strings.Repeat("A", 5001), 0)

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
	t.Logf("shared inserter stalled: EXCLUSIVE lock held on falco_events (stands in for DB contention/slowness)")

	s := escNewServer(pg)
	mux := http.NewServeMux()
	mux.HandleFunc("/ingestor/api/v1/push", newHandlePush(a, s))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := escClient()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	atok := escToken(t, key, attacker)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				escPost(client, srv.URL, atok, poison)
			}
		}()
	}
	time.Sleep(2500 * time.Millisecond)
	t.Logf("after tenant-A flood: shared channel occupancy = %d / 5000", len(s.eventChannel))

	vtok := escToken(t, key, victim)
	start := time.Now()
	code := escPost(client, srv.URL, vtok, escBody(victim, "valid victim telemetry", 0))
	elapsed := time.Since(start)
	t.Logf("victim-B push (valid event, own token) while tenant-A floods + inserter stalled: status=%d after %s",
		code, elapsed.Round(time.Millisecond))

	close(stop)
	wg.Wait()
	if _, err := lk.Exec(ctx, "ROLLBACK"); err != nil {
		t.Logf("rollback: %v", err)
	}
	lk.Release()
	escWaitDrain(s, 30*time.Second)

	if code != http.StatusInternalServerError {
		t.Errorf("expected the cross-tenant push to fail with 500 under a stalled inserter, got %d", code)
	}
}
