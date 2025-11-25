// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package encoding

import "testing"

// go test -v -cover -run=^TestBase64$
func TestBase64(t *testing.T) {
	testCases := []testCase{
		{Data: []byte{}, EncodingData: []byte{}},
		{Data: []byte("123"), EncodingData: []byte("MTIz")},
		{Data: []byte("你好，世界"), EncodingData: []byte("5L2g5aW977yM5LiW55WM")},
	}

	testEncoding(t, Base64, testCases)
}
