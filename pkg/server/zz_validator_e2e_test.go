// SPDX-License-Identifier: Apache-2.0
//
// VALIDATOR-ONLY test. Not part of upstream and not part of the hunter's PoC.
// It drives the REAL HTTP handler (newHandlePush) with two REAL signed RS256
// tokens (a victim tenant and an attacker tenant), shows both pushes get HTTP 200
// at enqueue time, and then shows the async drain drops the victim's event in the
// same batch as the attacker's store-fatal event.
//
// Run:  go test -v -run ValidatorE2E ./pkg/server/
package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gardener/falco-event-ingestor/pkg/auth"
	"github.com/gardener/falco-event-ingestor/pkg/postgres"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

func vKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	return k
}

func vAuth(t *testing.T, key *rsa.PrivateKey) *auth.Auth {
	t.Helper()
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
	return a
}

func vToken(t *testing.T, key *rsa.PrivateKey, clusterID string) string {
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

func vBody(t *testing.T, clusterID string, pad int) []byte {
	t.Helper()
	fields := map[string]interface{}{"cluster_id": clusterID}
	if pad > 0 {
		fields["pad"] = strings.Repeat("B", pad)
	}
	ev := map[string]interface{}{
		"uuid":          "123e4567-e89b-12d3-a456-426614174000",
		"output":        "validator e2e output",
		"priority":      "Notice",
		"rule":          "validator rule",
		"time":          time.Now().UTC().Format(time.RFC3339Nano),
		"output_fields": fields,
		"source":        "syscall",
		"tags":          []string{"container"},
		"hostname":      "falco-abcde",
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vNewServer() *Server {
	return &Server{
		eventChannel:   make(chan postgres.EventStruct, 16),
		postgres:       &postgres.PostgresConfig{},
		clusterLimits:  map[string]*clusterLimiter{},
		clusterLimit:   rate.Inf,
		clusterBurst:   1 << 30,
		generalLimiter: rate.NewLimiter(rate.Inf, 1<<30),
	}
}

func TestValidatorE2E_HTTP200ThenSilentCrossTenantDrop(t *testing.T) {
	const (
		attackerID = "shoot--attacker--attackercluster-11111111-1111-1111-1111-111111111111-garden-dev"
		victimID   = "shoot--victim--victimcluster-22222222-2222-2222-2222-222222222222-garden-dev"
	)
	key := vKey(t)
	a := vAuth(t, key)
	s := vNewServer()
	mux := http.NewServeMux()
	mux.HandleFunc("/ingestor/api/v1/push", newHandlePush(a, s))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	post := func(tok string, body []byte) int {
		req, err := http.NewRequest("POST", srv.URL+"/ingestor/api/v1/push", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if got := post(vToken(t, key, victimID), vBody(t, victimID, 0)); got != http.StatusOK {
		t.Fatalf("victim push: expected 200, got %d", got)
	}
	if got := post(vToken(t, key, attackerID), vBody(t, attackerID, 60000)); got != http.StatusOK {
		t.Fatalf("attacker poison push: expected 200, got %d", got)
	}
	if n := len(s.eventChannel); n != 2 {
		t.Fatalf("expected 2 events queued, got %d", n)
	}
	t.Logf("both tenants received HTTP 200; 2 events are queued, NO insert has run yet (writeEventToChannel is enqueue-only)")

	// The async drainer (readEventsFromChannel) now forms ONE batch from both
	// tenants' events. The attacker's oversized output_fields aborts Insert
	// before CopyFrom, so the victim event is never persisted.
	drained := len(s.eventChannel)
	panicked := func() (r interface{}) {
		defer func() { r = recover() }()
		s.insertEvents()
		return nil
	}()
	if panicked != nil {
		t.Fatalf("poison batch unexpectedly reached the DB layer: %v", panicked)
	}
	if len(s.eventChannel) != 0 {
		t.Fatalf("channel not fully drained (%d left of %d)", len(s.eventChannel), drained)
	}
	t.Logf("drain: %d events (victim + attacker, different tenants) formed ONE batch;", drained)
	t.Logf("       Insert aborted BEFORE CopyFrom -> the victim's event was silently lost;")
	t.Logf("       the only trace is the server log line 'Error inserting 2 event(s) ... too large'.")

	// Negative control: a batch of only valid events DOES reach the DB layer.
	s2 := vNewServer()
	s2.eventChannel <- mustParseTrusted(t, vBody(t, victimID, 0))
	ctrlPanic := func() (r interface{}) {
		defer func() { r = recover() }()
		s2.insertEvents()
		return nil
	}()
	if ctrlPanic == nil {
		t.Fatalf("control: a valid-only batch should have reached the DB layer")
	}
	t.Logf("CONTROL: a valid-only batch reached the DB layer (nil-pool sentinel: %v)", ctrlPanic)
}

// mustParseTrusted decodes a body the same way the handler does, so the control
// uses a genuine EventStruct rather than a hand-built one.
func mustParseTrusted(t *testing.T, body []byte) postgres.EventStruct {
	t.Helper()
	req := httptest.NewRequest("POST", "/ingestor/api/v1/push", bytes.NewReader(body))
	ev, err := requestToEvent(req)
	if err != nil {
		t.Fatalf("requestToEvent: %v", err)
	}
	return *ev
}
