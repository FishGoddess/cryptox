// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package bytes

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// go test -v -cover -count=1 -test.cpu=1 -run=^TestHex$
func TestHex(t *testing.T) {
	testCases := [][]byte{
		{},
		{1, 2, 3, 4, 5},
		{250, 251, 252, 253, 254, 255},
		[]byte("ABCDE"),
		[]byte("你好，世界"),
	}

	for _, testCase := range testCases {
		got := Hex(testCase)
		want := hex.EncodeToString(testCase)

		if got != want {
			t.Fatalf("got %s != want %s", got, want)
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestBase64$
func TestBase64(t *testing.T) {
	testCases := [][]byte{
		{},
		{1, 2, 3, 4, 5},
		{250, 251, 252, 253, 254, 255},
		[]byte("ABCDE"),
		[]byte("你好，世界"),
	}

	for _, testCase := range testCases {
		got := Base64(testCase)
		want := base64.StdEncoding.EncodeToString(testCase)

		if got != want {
			t.Fatalf("got %s != want %s", got, want)
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestParseHex$
func TestParseHex(t *testing.T) {
	testCases := [][]byte{
		{},
		{1, 2, 3, 4, 5},
		{250, 251, 252, 253, 254, 255},
		[]byte("ABCDE"),
		[]byte("你好，世界"),
	}

	for _, testCase := range testCases {
		str := hex.EncodeToString(testCase)

		got, err := ParseHex(str)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(got, testCase) {
			t.Fatalf("got %+v != testCase %+v", got, testCase)
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestParseBase64$
func TestParseBase64(t *testing.T) {
	testCases := [][]byte{
		{},
		{1, 2, 3, 4, 5},
		{250, 251, 252, 253, 254, 255},
		[]byte("ABCDE"),
		[]byte("你好，世界"),
	}

	for _, testCase := range testCases {
		str := base64.StdEncoding.EncodeToString(testCase)

		got, err := ParseBase64(str)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(got, testCase) {
			t.Fatalf("got %+v != testCase %+v", got, testCase)
		}
	}
}
