// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// PoC harness for falco-event-ingestor. This file is NOT part of upstream.
package auth

import (
	"fmt"
	"strings"
	"testing"
)

// PoC: VerifyToken indexes parts[2] of strings.Split(tokenString, ".") with no
// length check, so any bearer token with fewer than three "."-separated segments
// panics - before any signature is checked. Reached from the public
// /ingestor/api/v1/push handler.
func TestPoC_MalformedTokenIndexPanic(t *testing.T) {
	a := NewAuth()
	for _, tok := range []string{"x", "a.b", "", "not-a-jwt"} {
		tok := tok
		rec := func() (r interface{}) {
			defer func() { r = recover() }()
			_, _ = a.VerifyToken(tok)
			return nil
		}()
		if rec == nil {
			t.Errorf("token %q was handled without a panic", tok)
			continue
		}
		// <2 segments panic on parts[0:2] (line 107); exactly 2 segments panic on
		// parts[2] (line 109). Both are the same missing length check.
		if !strings.Contains(fmt.Sprint(rec), "out of range") {
			t.Errorf("token %q panicked with an unexpected value: %v", tok, rec)
			continue
		}
		t.Logf("token %q -> panic before signature verification: %v", tok, rec)
	}
}
