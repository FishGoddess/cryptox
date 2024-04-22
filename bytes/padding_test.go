// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package bytes

import (
	"bytes"
	"testing"
)

type paddingTestCase struct {
	Data []byte
	Want []byte
}

func testPadding(t *testing.T, padding Padding, testCases []paddingTestCase) {
	blockSize := 8

	for _, testCase := range testCases {
		got := padding.Padding(testCase.Data, blockSize)
		if !bytes.Equal(got, testCase.Want) {
			t.Fatalf("got %+v != want %+v", got, testCase.Want)
		}

		got, err := padding.UndoPadding(got, blockSize)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(got, testCase.Data) {
			t.Fatalf("got %+v != data %+v", got, testCase.Data)
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestPaddingNone$
func TestPaddingNone(t *testing.T) {
	testCases := []paddingTestCase{
		{Data: []byte{}, Want: []byte{}},
		{Data: []byte{1, 2, 3, 4, 5}, Want: []byte{1, 2, 3, 4, 5}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}, Want: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}, Want: []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}},
	}

	padding := PaddingNone()
	testPadding(t, padding, testCases)
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestPaddingZero$
func TestPaddingZero(t *testing.T) {
	testCases := []paddingTestCase{
		{Data: []byte{}, Want: []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{Data: []byte{1, 2, 3, 4, 5}, Want: []byte{1, 2, 3, 4, 5, 0, 0, 0}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}, Want: []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}, Want: []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	}

	padding := PaddingZero()
	testPadding(t, padding, testCases)
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestPaddingPKCS5$
func TestPaddingPKCS5(t *testing.T) {
	testCases := []paddingTestCase{
		{Data: []byte{}, Want: []byte{8, 8, 8, 8, 8, 8, 8, 8}},
		{Data: []byte{1, 2, 3, 4, 5}, Want: []byte{1, 2, 3, 4, 5, 3, 3, 3}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}, Want: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}, Want: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8}},
	}

	padding := PaddingPKCS5()
	testPadding(t, padding, testCases)
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestPaddingPKCS7$
func TestPaddingPKCS7(t *testing.T) {
	testCases := []paddingTestCase{
		{Data: []byte{}, Want: []byte{8, 8, 8, 8, 8, 8, 8, 8}},
		{Data: []byte{1, 2, 3, 4, 5}, Want: []byte{1, 2, 3, 4, 5, 3, 3, 3}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}, Want: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}, Want: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8}},
	}

	padding := PaddingPKCS7()
	testPadding(t, padding, testCases)
}
