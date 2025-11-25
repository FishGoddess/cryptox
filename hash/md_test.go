// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"crypto/md5"
	"slices"
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
)

// go test -v -cover -run=^TestMD5$
func TestMD5(t *testing.T) {
	testCases := map[string][]byte{
		"":      []byte("d41d8cd98f00b204e9800998ecf8427e"),
		"123":   []byte("202cb962ac59075b964b07152d234b70"),
		"你好，世界": []byte("dbefd3ada018615b35588a01e216ae6e"),
	}

	for data, expect := range testCases {
		got := MD5([]byte(data), encoding.Hex)
		if !slices.Equal(got, expect) {
			t.Fatalf("data %s: got %s != expect %s", data, got, expect)
		}

		h := md5.New()
		h.Write([]byte(data))

		expect = h.Sum(nil)
		expect = encoding.Hex.Encode(expect)
		if !slices.Equal(got, expect) {
			t.Fatalf("data %s: got %s != expect %s", data, got, expect)
		}
	}
}
