// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package encoding

import "testing"

// go test -v -cover -run=^TestNone$
func TestNone(t *testing.T) {
	testCases := []testCase{
		{Data: []byte{}, EncodingData: []byte{}},
		{Data: []byte("123"), EncodingData: []byte("123")},
		{Data: []byte("你好，世界"), EncodingData: []byte("你好，世界")},
	}

	testEncoding(t, None, testCases)
}
