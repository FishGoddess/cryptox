// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hmac

import (
	"crypto/md5"
	"encoding/hex"
	"testing"
)

// go test -v -cover -run=^TestHMAC$
func TestHMAC(t *testing.T) {
	testCases := map[string]string{
		"":      "63530468a04e386459855da0063b6596",
		"123":   "52851cb05258c8d98da1672d95729e53",
		"你好，世界": "e76d8f84103533dc5d22a6e00cef74f3",
	}

	key := []byte("key")
	for input, expect := range testCases {
		sum, err := hmac(md5.New, key, []byte(input))
		if err != nil {
			t.Error(err)
		}

		sumHex := hex.EncodeToString(sum)
		if sumHex != expect {
			t.Errorf("input %s: sumHex %s != expect %s", input, sumHex, expect)
		}
	}
}
