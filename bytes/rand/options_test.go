// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rand

import (
	"testing"
)

// go test -v -cover -run=^TestConfig$
func TestConfig(t *testing.T) {
	opts := []Option{
		WithWeak(),
	}

	conf := newConfig().Apply(opts...)

	if !conf.weak {
		t.Fatalf("got %v != expect %v", conf.weak, true)
	}
}
