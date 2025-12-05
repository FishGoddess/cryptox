// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"fmt"
	"slices"
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/bytes/padding"
)

// go test -v -cover -run=^TestConfig$
func TestConfig(t *testing.T) {
	additional := []byte("additional")

	opts := []Option{
		WithHex(),
		WithZero(),
		WithAdditional(additional),
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

	got = fmt.Sprintf("%T", conf.padding)
	expect = fmt.Sprintf("%T", padding.Zero{})
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}

	conf.Apply(WithPKCS5())

	got = fmt.Sprintf("%T", conf.padding)
	expect = fmt.Sprintf("%T", padding.PKCS5{})
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}

	conf.Apply(WithPKCS7())

	got = fmt.Sprintf("%T", conf.padding)
	expect = fmt.Sprintf("%T", padding.PKCS7{})
	if got != expect {
		t.Fatalf("got %s != expect %s", got, expect)
	}

	if !slices.Equal(conf.additional, additional) {
		t.Fatalf("got %s != expect %s", conf.additional, additional)
	}
}
