// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"testing"

	"github.com/FishGoddess/cryptox/v2/bytes"
)

// go test -v -cover -run=^TestMD5HMAC$
func TestMD5HMAC(t *testing.T) {
	cases := map[string]string{
		"":      "63530468a04e386459855da0063b6596",
		"123":   "52851cb05258c8d98da1672d95729e53",
		"你好，世界": "e76d8f84103533dc5d22a6e00cef74f3",
	}

	key := bytes.FromString("key")
	for input, expect := range cases {
		sum, err := MD5HMAC(key, bytes.FromString(input))
		if err != nil {
			t.Error(err)
		}

		if sum.Hex() != expect {
			t.Errorf("input %s: sum.Hex() %s != expect %s", input, sum.Hex(), expect)
		}
	}
}

// go test -v -cover -run=^TestSHA256HMAC$
func TestSHA256HMAC(t *testing.T) {
	cases := map[string]string{
		"":      "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0",
		"123":   "a7f7739b1dc5b4e922b1226c9fcbdc83498dee375382caee08fd52a13eb7cfe2",
		"你好，世界": "ecebc269659999d50a6f74743f5814cf08000c7f7da1bf4efd46ed651778ed94",
	}

	key := bytes.FromString("key")
	for input, expect := range cases {
		sum, err := SHA256HMAC(key, bytes.FromString(input))
		if err != nil {
			t.Error(err)
		}

		if sum.Hex() != expect {
			t.Errorf("input %s: sum.Hex() %s != expect %s", input, sum.Hex(), expect)
		}
	}
}
