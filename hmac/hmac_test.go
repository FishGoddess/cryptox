// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hmac

import (
	"bytes"
	"crypto/md5"
	"testing"
)

// go test -v -cover -run=^TestHMAC$
func TestHMAC(t *testing.T) {
	testCases := map[string][]byte{
		"":      {99, 83, 4, 104, 160, 78, 56, 100, 89, 133, 93, 160, 6, 59, 101, 150},
		"123":   {82, 133, 28, 176, 82, 88, 200, 217, 141, 161, 103, 45, 149, 114, 158, 83},
		"你好，世界": {231, 109, 143, 132, 16, 53, 51, 220, 93, 34, 166, 224, 12, 239, 116, 243},
	}

	key := []byte("key")
	for input, expect := range testCases {
		sum, err := hmac(md5.New, key, []byte(input))
		if err != nil {
			t.Error(err)
		}

		if !bytes.Equal(sum, expect) {
			t.Errorf("input %s: sum %+v != expect %+v", input, sum, expect)
		}
	}
}
