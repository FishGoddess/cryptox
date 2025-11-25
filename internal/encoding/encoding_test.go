// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package encoding

import (
	"slices"
	"testing"
)

type testCase struct {
	Data         []byte
	EncodingData []byte
}

func testEncoding(t *testing.T, encoding Encoding, testCases []testCase) {
	for _, testCase := range testCases {
		got := encoding.Encode(testCase.Data)
		want := testCase.EncodingData

		if !slices.Equal(got, want) {
			t.Fatalf("got %+v != want %+v", got, want)
		}

		got, err := encoding.Decode(got)
		if err != nil {
			t.Fatal(err)
		}

		want = testCase.Data
		if !slices.Equal(got, want) {
			t.Fatalf("got %+v != want %+v", got, want)
		}
	}
}
