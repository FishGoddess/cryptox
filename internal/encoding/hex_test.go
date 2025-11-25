// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package encoding

import "testing"

// go test -v -cover -run=^TestHex$
func TestHex(t *testing.T) {
	testCases := []testCase{
		{Data: []byte{}, EncodingData: []byte{}},
		{Data: []byte("Hello World"), EncodingData: []byte("48656c6c6f20576f726c64")},
		{Data: []byte("你好，世界"), EncodingData: []byte("e4bda0e5a5bdefbc8ce4b896e7958c")},
	}

	testEncoding(t, Hex, testCases)
}
