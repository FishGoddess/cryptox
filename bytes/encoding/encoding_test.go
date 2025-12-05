// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package encoding

import (
	"fmt"
	"slices"
	"testing"
)

type testCase struct {
	Data         []byte
	EncodingData []byte
}

func testEncoding(name string, encoding Encoding, testCases []testCase) error {
	for _, testCase := range testCases {
		got := encoding.Encode(testCase.Data)
		want := testCase.EncodingData

		if !slices.Equal(got, want) {
			return fmt.Errorf("%s data %q: got %+v != want %+v", name, testCase.Data, got, want)
		}

		got, err := encoding.Decode(got)
		if err != nil {
			return err
		}

		want = testCase.Data
		if !slices.Equal(got, want) {
			return fmt.Errorf("%s data %q: got %+v != want %+v", name, testCase.Data, got, want)
		}
	}

	return nil
}

// go test -v -cover -run=^TestNone$
func TestNone(t *testing.T) {
	testCases := []testCase{
		{Data: []byte{}, EncodingData: []byte{}},
		{Data: []byte("123"), EncodingData: []byte("123")},
		{Data: []byte("你好，世界"), EncodingData: []byte("你好，世界")},
	}

	if err := testEncoding(t.Name(), None{}, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestHex$
func TestHex(t *testing.T) {
	testCases := []testCase{
		{Data: []byte{}, EncodingData: []byte{}},
		{Data: []byte("123"), EncodingData: []byte("313233")},
		{Data: []byte("你好，世界"), EncodingData: []byte("e4bda0e5a5bdefbc8ce4b896e7958c")},
	}

	if err := testEncoding(t.Name(), Hex{}, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestBase64$
func TestBase64(t *testing.T) {
	testCases := []testCase{
		{Data: []byte{}, EncodingData: []byte{}},
		{Data: []byte("123"), EncodingData: []byte("MTIz")},
		{Data: []byte("你好，世界"), EncodingData: []byte("5L2g5aW977yM5LiW55WM")},
	}

	if err := testEncoding(t.Name(), Base64{}, testCases); err != nil {
		t.Fatal(err)
	}
}
