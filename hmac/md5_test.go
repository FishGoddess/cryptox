// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hmac

import (
	"bytes"
	"testing"
)

// go test -v -cover -run=^TestMD5$
func TestMD5(t *testing.T) {
	testCases := map[string][]byte{
		"":      {99, 83, 4, 104, 160, 78, 56, 100, 89, 133, 93, 160, 6, 59, 101, 150},
		"123":   {82, 133, 28, 176, 82, 88, 200, 217, 141, 161, 103, 45, 149, 114, 158, 83},
		"你好，世界": {231, 109, 143, 132, 16, 53, 51, 220, 93, 34, 166, 224, 12, 239, 116, 243},
	}

	key := []byte("key")
	for input, expect := range testCases {
		sum, err := MD5(key, []byte(input))
		if err != nil {
			t.Error(err)
		}

		if !bytes.Equal(sum, expect) {
			t.Errorf("input %s: sum %+v != expect %+v", input, sum, expect)
		}
	}
}

// go test -v -cover -run=^TestMD5Hex$
func TestMD5Hex(t *testing.T) {
	testCases := map[string]string{
		"":      "63530468a04e386459855da0063b6596",
		"123":   "52851cb05258c8d98da1672d95729e53",
		"你好，世界": "e76d8f84103533dc5d22a6e00cef74f3",
	}

	key := []byte("key")
	for input, expect := range testCases {
		sum, err := MD5Hex(key, []byte(input))
		if err != nil {
			t.Error(err)
		}

		if sum != expect {
			t.Errorf("input %s: sum %s != expect %s", input, sum, expect)
		}
	}
}

// go test -v -cover -run=^TestMD5Base64$
func TestMD5Base64(t *testing.T) {
	testCases := map[string]string{
		"":      "Y1MEaKBOOGRZhV2gBjtllg==",
		"123":   "UoUcsFJYyNmNoWctlXKeUw==",
		"你好，世界": "522PhBA1M9xdIqbgDO908w==",
	}

	key := []byte("key")
	for input, expect := range testCases {
		sum, err := MD5Base64(key, []byte(input))
		if err != nil {
			t.Error(err)
		}

		if sum != expect {
			t.Errorf("input %s: sum %s != expect %s", input, sum, expect)
		}
	}
}
