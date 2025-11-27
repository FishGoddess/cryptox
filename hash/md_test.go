// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"fmt"
	"slices"
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
)

type testHashFunc = func(bs []byte, encoding encoding.Encoding) []byte

type testCase struct {
	Data           []byte
	HashData       []byte
	HashDataHex    []byte
	HashDataBase64 []byte
}

func testHash(name string, hash testHashFunc, testCases []testCase) error {
	for _, testCase := range testCases {
		// None
		got := hash([]byte(testCase.Data), encoding.None)
		if !slices.Equal(got, testCase.HashData) {
			return fmt.Errorf("%s data %q: got %+v != expect %+v", name, testCase.Data, got, testCase.HashData)
		}

		// Hex
		got = hash([]byte(testCase.Data), encoding.Hex)
		if !slices.Equal(got, testCase.HashDataHex) {
			return fmt.Errorf("%s data %q: got hex %s != expect hex %s", name, testCase.Data, got, testCase.HashDataHex)
		}

		// Base64
		got = hash([]byte(testCase.Data), encoding.Base64)
		if !slices.Equal(got, testCase.HashDataBase64) {
			return fmt.Errorf("%s data %q: got base64 %s != expect base64 %s", name, testCase.Data, got, testCase.HashDataBase64)
		}
	}

	return nil
}

// go test -v -cover -run=^TestMD5$
func TestMD5(t *testing.T) {
	testCases := []testCase{
		{
			Data:           []byte(""),
			HashData:       []byte{212, 29, 140, 217, 143, 0, 178, 4, 233, 128, 9, 152, 236, 248, 66, 126},
			HashDataHex:    []byte("d41d8cd98f00b204e9800998ecf8427e"),
			HashDataBase64: []byte("1B2M2Y8AsgTpgAmY7PhCfg=="),
		},
		{
			Data:           []byte("123"),
			HashData:       []byte{32, 44, 185, 98, 172, 89, 7, 91, 150, 75, 7, 21, 45, 35, 75, 112},
			HashDataHex:    []byte("202cb962ac59075b964b07152d234b70"),
			HashDataBase64: []byte("ICy5YqxZB1uWSwcVLSNLcA=="),
		},
		{
			Data:           []byte("你好，世界"),
			HashData:       []byte{219, 239, 211, 173, 160, 24, 97, 91, 53, 88, 138, 1, 226, 22, 174, 110},
			HashDataHex:    []byte("dbefd3ada018615b35588a01e216ae6e"),
			HashDataBase64: []byte("2+/TraAYYVs1WIoB4haubg=="),
		},
	}

	if err := testHash(t.Name(), MD5, testCases); err != nil {
		t.Fatal(err)
	}
}
