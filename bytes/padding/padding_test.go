// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package padding

import (
	"fmt"
	"slices"
	"testing"
)

type testCase struct {
	Data        []byte
	PaddingData []byte
}

func testPadding(name string, blockSize int, padding Padding, testCases []testCase) error {
	for _, testCase := range testCases {
		got := padding.Pad(testCase.Data, blockSize)
		want := testCase.PaddingData

		if !slices.Equal(got, want) {
			return fmt.Errorf("%s data %+v: got %+v != want %+v", name, testCase.Data, got, want)
		}

		got, err := padding.Unpad(got, blockSize)
		if err != nil {
			return err
		}

		want = testCase.Data
		if !slices.Equal(got, want) {
			return fmt.Errorf("%s data %+v: got %+v != want %+v", name, testCase.Data, got, want)
		}
	}

	return nil
}

// go test -v -cover -run=^TestNone$
func TestNone(t *testing.T) {
	testCases := []testCase{
		{
			Data:        []byte{},
			PaddingData: []byte{},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5},
			PaddingData: []byte{1, 2, 3, 4, 5},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8},
			PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1},
			PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1},
		},
	}

	if err := testPadding(t.Name(), 8, None{}, testCases); err != nil {
		t.Fatal(err)
	}

	testCases = []testCase{
		{
			Data:        []byte{},
			PaddingData: []byte{},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5},
			PaddingData: []byte{1, 2, 3, 4, 5},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8},
			PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1},
			PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1},
		},
	}

	if err := testPadding(t.Name(), 16, None{}, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestZero$
func TestZero(t *testing.T) {
	testCases := []testCase{
		{
			Data:        []byte{},
			PaddingData: []byte{},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5},
			PaddingData: []byte{1, 2, 3, 4, 5, 0, 0, 0},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8},
			PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1},
			PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1},
		},
	}

	if err := testPadding(t.Name(), 8, Zero{}, testCases); err != nil {
		t.Fatal(err)
	}

	testCases = []testCase{
		{
			Data:        []byte{},
			PaddingData: []byte{},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5},
			PaddingData: []byte{1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8},
			PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1},
			PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1},
		},
	}

	if err := testPadding(t.Name(), 16, Zero{}, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestPKCS5$
func TestPKCS5(t *testing.T) {
	testCases := []testCase{
		{
			Data:        []byte{},
			PaddingData: []byte{8, 8, 8, 8, 8, 8, 8, 8},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5},
			PaddingData: []byte{1, 2, 3, 4, 5, 3, 3, 3},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8},
			PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1},
			PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1, 8, 8, 8, 8, 8, 8, 8, 8},
		},
	}

	if err := testPadding(t.Name(), 8, PKCS5{}, testCases); err != nil {
		t.Fatal(err)
	}

	testCases = []testCase{
		{
			Data:        []byte{},
			PaddingData: []byte{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5},
			PaddingData: []byte{1, 2, 3, 4, 5, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8},
			PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1},
			PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
		},
	}

	if err := testPadding(t.Name(), 16, PKCS5{}, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestPKCS7$
func TestPKCS7(t *testing.T) {
	testCases := []testCase{
		{
			Data:        []byte{},
			PaddingData: []byte{8, 8, 8, 8, 8, 8, 8, 8},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5},
			PaddingData: []byte{1, 2, 3, 4, 5, 3, 3, 3},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8},
			PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1},
			PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1, 8, 8, 8, 8, 8, 8, 8, 8},
		},
	}

	if err := testPadding(t.Name(), 8, PKCS7{}, testCases); err != nil {
		t.Fatal(err)
	}

	testCases = []testCase{
		{
			Data:        []byte{},
			PaddingData: []byte{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5},
			PaddingData: []byte{1, 2, 3, 4, 5, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8},
			PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8},
		},
		{
			Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1},
			PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 1, 1, 1, 1, 1, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
		},
	}

	if err := testPadding(t.Name(), 16, PKCS5{}, testCases); err != nil {
		t.Fatal(err)
	}
}
