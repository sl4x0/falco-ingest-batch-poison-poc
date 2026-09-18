# falco-event-ingestor — batch-poison / no-boundary-validation PoC harness

Target: `github.com/gardener/falco-event-ingestor` at commit **a70f6443e36457ee6aca4d1658ee1534eaec8e1c**
(2026-07-29, "Adapt VPA resources to explicitly specify update mode `InPlaceOrRecreate` (#209)").

## Why this harness is a copy

`verifyEventTokenMatch`, `requestToEvent`, `insertEvents` and `parseClusterId` are unexported,
and the upstream `pkg/server` test suite never executes (see "Inert upstream tests" below), so a
test added to the clone would never run either. `src/` is a copy of the repository with **one**
byte-level deviation, and everything else identical:

    pkg/server/server_test.go — TestMain now ends with os.Exit(m.Run()) (+ the "os" import).

All files under test are unmodified. sha256 of the files that carry the findings:

    03ABA1FBB0AC90E9...  pkg/server/server.go
    8D9A53B800636907...  pkg/postgres/postgres.go
    3C2B43AD82C67F79...  pkg/auth/validation.go
    656535BCDE08D5D6...  pkg/metrics/metrics.go

`src/` is a self-contained Go module; the module cache already holds the dependencies.

## Run

    cd src
    go test -v -count=1 -run 'PoC' ./pkg/...

Expected: the six `TestPoC_*` tests all PASS. (The `-run 'PoC'` filter keeps the upstream
`pkg/server` tests out of the run; those are broken independently — see below.)

## What each test proves

| Test | Proves |
|---|---|
| `pkg/postgres` `TestPoC_InsertAbortsWholeBatchBeforeCopyFrom` | `Insert` returns the size error *before* `CopyFrom` for a poisoned batch, while an identical batch without the poison event does reach `CopyFrom`. CopyFrom is atomic → the whole batch is lost. |
| `pkg/postgres` `TestPoC_ParsedProjectCanOverflowVarchar50` | `parseClusterId` accepts an attacker-shaped identity whose parsed `project` is 53 chars → `varchar(50)` overflow (PG 22001) → same batch abort. |
| `pkg/server` `TestPoC_HTTPBoundaryAcceptsStoreFatalEvent` | The ingest boundary accepts an event with `output` = 6001 chars (`message varchar(5000)`) and marshalled `output_fields` = 60106 bytes (`MAX_JSONB_SIZE` = 51200). No per-field limit at the boundary. |
| `pkg/server` `TestPoC_BatchPoison_DropsVictimEvents` | Two victim events + one attacker poison event are drained into ONE batch and the DB layer is never reached → the victim events are silently dropped. Control: the same two victim events alone *do* reach the DB layer. |
| `pkg/server` `TestPoC_UnboundedRequestBodyAccepted` | A 32 MiB request body is fully materialised; no `MaxBytesReader`/`io.LimitReader` exists anywhere in the module. |
| `pkg/server` `TestPoC_MalformedBearerToken_PanicsBeforeAuth` | `Authorization: Bearer x` and `Bearer a.b` panic the push handler before any signature check; net/http recovers per connection, the server keeps serving. |

The DB layer is substituted with a closed pool (`host=127.0.0.1 port=1`) and, in the server
package, with a `nil *pgxpool.Pool`. Reaching the DB layer therefore either returns a
`failed to insert events: ... dial error` or panics (`pgxpool.Pool.Acquire` dereferences the nil
receiver), which is used as an observable "CopyFrom was reached / was not reached" signal.

## Inert upstream tests (supporting observation)

    # clone: reports ok, but no test ever runs (TestMain returns without m.Run())
    cd <clone> && go test -v -count=1 ./pkg/server/      # -> "ok", zero "=== RUN" lines

    # harness copy, TestMain restored:
    cd src && go test -v -count=1 -run 'TestTokenEventMatch|TestRequestToEventGood' ./pkg/server/
    # -> TestTokenEventMatch  FAIL: "could not parse cluster id: invalid syntax"
    # -> TestRequestToEventGood FAIL: fixture bodyJson is not valid JSON

So the cluster-id match logic and the request decoder have never been exercised by CI.

## Not run here (needs live infrastructure)

* A real PostgreSQL with the `falco-event-db-schema` DDL. The `varchar(50/255/80/30/126/50/5000)`
  and `uuid` column limits are enforced by PostgreSQL, not by the ingestor; the harness proves the
  *consequence* (batch abort / silent drop) with the one size check that lives in Go, and proves the
  schema-overflow is reachable by showing the parsed values.
* Real concurrency for the sustained-loss claim (batches must contain a victim event and a poison
  event). The single-batch mechanics are proven; the sustained variant is argued from the shared
  channel + fast drain loop.
