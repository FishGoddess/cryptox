// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"bytes"
	"testing"
)

type paddingTestCase struct {
	Data Bytes
	Want Bytes
}

func testPadding(t *testing.T, padding Padding, testCases []paddingTestCase) {
	blockSize := 8

	for _, testCase := range testCases {
		got := padding.Padding(testCase.Data, blockSize)
		if !bytes.Equal(got, testCase.Want) {
			t.Fatalf("got %+v != want %+v", got, testCase.Want)
		}

		gotUndo, err := padding.UndoPadding(got, blockSize)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(gotUndo, testCase.Data) {
			t.Fatalf("gotUndo %+v != data %+v", gotUndo, testCase.Data)
		}
	}
}

// go test -v -cover -run=^TestPaddingNone$
func TestPaddingNone(t *testing.T) {
	testCases := []paddingTestCase{
		{Data: Bytes{}, Want: Bytes{}},
		{Data: Bytes{1, 2, 3, 4, 5}, Want: Bytes{1, 2, 3, 4, 5}},
		{Data: Bytes{1, 2, 3, 4, 5, 6, 7, 8}, Want: Bytes{1, 2, 3, 4, 5, 6, 7, 8}},
		{Data: Bytes{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}, Want: Bytes{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}},
	}

	testPadding(t, PaddingNone, testCases)
}

// go test -v -cover -run=^TestPaddingZero$
func TestPaddingZero(t *testing.T) {
	testCases := []paddingTestCase{
		{Data: Bytes{}, Want: Bytes{0, 0, 0, 0, 0, 0, 0, 0}},
		{Data: Bytes{1, 2, 3, 4, 5}, Want: Bytes{1, 2, 3, 4, 5, 0, 0, 0}},
		{Data: Bytes{1, 2, 3, 4, 5, 6, 7, 8}, Want: Bytes{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}},
		{Data: Bytes{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}, Want: Bytes{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	}

	testPadding(t, PaddingZero, testCases)
}

// go test -v -cover -run=^TestPaddingPKCS5$
func TestPaddingPKCS5(t *testing.T) {
	testCases := []paddingTestCase{
		{Data: Bytes{}, Want: Bytes{8, 8, 8, 8, 8, 8, 8, 8}},
		{Data: Bytes{1, 2, 3, 4, 5}, Want: Bytes{1, 2, 3, 4, 5, 3, 3, 3}},
		{Data: Bytes{1, 2, 3, 4, 5, 6, 7, 8}, Want: Bytes{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}},
		{Data: Bytes{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}, Want: Bytes{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8}},
	}

	testPadding(t, PaddingPKCS5, testCases)
}

// go test -v -cover -run=^TestPaddingPKCS7$
func TestPaddingPKCS7(t *testing.T) {
	testCases := []paddingTestCase{
		{Data: Bytes{}, Want: Bytes{8, 8, 8, 8, 8, 8, 8, 8}},
		{Data: Bytes{1, 2, 3, 4, 5}, Want: Bytes{1, 2, 3, 4, 5, 3, 3, 3}},
		{Data: Bytes{1, 2, 3, 4, 5, 6, 7, 8}, Want: Bytes{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}},
		{Data: Bytes{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}, Want: Bytes{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8}},
	}

	testPadding(t, PaddingPKCS7, testCases)
}
