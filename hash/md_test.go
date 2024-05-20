// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import "testing"

// go test -v -cover -count=1 -test.cpu=1 -run=^TestMD5$
func TestMD5(t *testing.T) {
	cases := map[string]string{
		"":      "d41d8cd98f00b204e9800998ecf8427e",
		"123":   "202cb962ac59075b964b07152d234b70",
		"你好，世界": "dbefd3ada018615b35588a01e216ae6e",
	}

	for input, expect := range cases {
		sum := MD5([]byte(input))
		if sum.Hex() != expect {
			t.Fatalf("input %s: sum.Hex() %s != expect %s", input, sum.Hex(), expect)
		}
	}
}
