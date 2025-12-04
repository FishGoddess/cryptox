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

// go test -v -cover -run=^TestNone$
func TestNone(t *testing.T) {
	testCases := []testCase{
		{Data: []byte{}, PaddingData: []byte{}},
		{Data: []byte{1, 2, 3, 4, 5}, PaddingData: []byte{1, 2, 3, 4, 5}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}, PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}, PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}},
	}

	testPadding(t, None{}, testCases)
}

// go test -v -cover -run=^TestZero$
func TestZero(t *testing.T) {
	testCases := []testCase{
		{Data: []byte{}, PaddingData: []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{Data: []byte{1, 2, 3, 4, 5}, PaddingData: []byte{1, 2, 3, 4, 5, 0, 0, 0}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}, PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}, PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	}

	testPadding(t, Zero{}, testCases)
}

// go test -v -cover -run=^TestPKCS5$
func TestPKCS5(t *testing.T) {
	testCases := []testCase{
		{Data: []byte{}, PaddingData: []byte{8, 8, 8, 8, 8, 8, 8, 8}},
		{Data: []byte{1, 2, 3, 4, 5}, PaddingData: []byte{1, 2, 3, 4, 5, 3, 3, 3}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}, PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}, PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8}},
	}

	testPadding(t, PKCS5{}, testCases)
}

// go test -v -cover -run=^TestPKCS7$
func TestPKCS7(t *testing.T) {
	testCases := []testCase{
		{Data: []byte{}, PaddingData: []byte{8, 8, 8, 8, 8, 8, 8, 8}},
		{Data: []byte{1, 2, 3, 4, 5}, PaddingData: []byte{1, 2, 3, 4, 5, 3, 3, 3}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}, PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}, PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8}},
	}

	testPadding(t, PKCS7{}, testCases)
}
