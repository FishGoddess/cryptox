// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package padding

import "testing"

// go test -v -cover -run=^TestNone$
func TestNone(t *testing.T) {
	testCases := []testCase{
		{Data: []byte{}, PaddingData: []byte{}},
		{Data: []byte{1, 2, 3, 4, 5}, PaddingData: []byte{1, 2, 3, 4, 5}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}, PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}, PaddingData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}},
	}

	testPadding(t, None, testCases)
}
