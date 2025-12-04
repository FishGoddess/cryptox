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

// go test -v -cover -run=^TestNone$
func TestNone(t *testing.T) {
	testCases := []testCase{
		{Data: []byte{}, EncodingData: []byte{}},
		{Data: []byte("123"), EncodingData: []byte("123")},
		{Data: []byte("你好，世界"), EncodingData: []byte("你好，世界")},
	}

	testEncoding(t, None{}, testCases)
}

// go test -v -cover -run=^TestHex$
func TestHex(t *testing.T) {
	testCases := []testCase{
		{Data: []byte{}, EncodingData: []byte{}},
		{Data: []byte("123"), EncodingData: []byte("313233")},
		{Data: []byte("你好，世界"), EncodingData: []byte("e4bda0e5a5bdefbc8ce4b896e7958c")},
	}

	testEncoding(t, Hex{}, testCases)
}

// go test -v -cover -run=^TestBase64$
func TestBase64(t *testing.T) {
	testCases := []testCase{
		{Data: []byte{}, EncodingData: []byte{}},
		{Data: []byte("123"), EncodingData: []byte("MTIz")},
		{Data: []byte("你好，世界"), EncodingData: []byte("5L2g5aW977yM5LiW55WM")},
	}

	testEncoding(t, Base64{}, testCases)
}
