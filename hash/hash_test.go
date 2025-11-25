// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"slices"
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
)

type testHashFunc = func(bs []byte, encoding encoding.Encoding) []byte

type testCase struct {
	Data     []byte
	Expect   []byte
	Encoding encoding.Encoding
}

func testHash(t *testing.T, hash testHashFunc, testCases []testCase) {
	for _, testCase := range testCases {
		got := hash([]byte(testCase.Data), testCase.Encoding)
		if !slices.Equal(got, testCase.Expect) {
			t.Fatalf("data %s: got %s != expect %s", testCase.Data, got, testCase.Expect)
		}
	}
}
