// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package padding

import (
	"slices"
	"testing"
)

type testCase struct {
	Data        []byte
	PaddingData []byte
}

func testPadding(t *testing.T, padding Padding, testCases []testCase) {
	blockSize := 8

	for _, testCase := range testCases {
		got := padding.Pad(testCase.Data, blockSize)
		want := testCase.PaddingData

		if !slices.Equal(got, want) {
			t.Fatalf("got %+v != want %+v", got, want)
		}

		got, err := padding.Unpad(got, blockSize)
		if err != nil {
			t.Fatal(err)
		}

		want = testCase.Data
		if !slices.Equal(got, want) {
			t.Fatalf("got %+v != want %+v", got, want)
		}
	}
}
