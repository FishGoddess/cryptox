// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hmac

import (
	"fmt"
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
)

// go test -v -cover -run=^TestConfig$
func TestConfig(t *testing.T) {
	opts := []Option{
		WithHex(),
	}

	conf := newConfig().Apply(opts...)

	got := fmt.Sprintf("%T", conf.encoding)
	expect := fmt.Sprintf("%T", encoding.Hex{})
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}

	conf.Apply(WithBase64())

	got = fmt.Sprintf("%T", conf.encoding)
	expect = fmt.Sprintf("%T", encoding.Base64{})
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}
}
