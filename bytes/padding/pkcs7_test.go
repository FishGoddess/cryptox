// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package padding

import "testing"

// go test -v -cover -run=^TestPKCS7$
func TestPKCS7(t *testing.T) {
	testCases := []testCase{
		{Data: []byte{}, PaddingData: []byte{8, 8, 8, 8, 8, 8, 8, 8}},
		{Data: []byte{1, 2, 3, 4, 5}, PaddingData: []byte{1, 2, 3, 4, 5, 3, 3, 3}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}, PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}, PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8}},
	}

	testPadding(t, PKCS7, testCases)
}
