// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"testing"
)

// go test -v -cover -count=1 -test.cpu=1 -run=^TestGenerateGCMNonce$
func TestGenerateGCMNonce(t *testing.T) {
	nonce := GenerateGCMNonce()
	if len(nonce) != 12 {
		t.Fatalf("len(nonce) %d is wrong", len(nonce))
	}

	t.Log(nonce)
}
