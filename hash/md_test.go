// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
)

// go test -v -cover -run=^TestMD5$
func TestMD5(t *testing.T) {
	testCases := []testCase{
		{Data: []byte(""), Expect: []byte("d41d8cd98f00b204e9800998ecf8427e"), Encoding: encoding.Hex},
		{Data: []byte("123"), Expect: []byte("202cb962ac59075b964b07152d234b70"), Encoding: encoding.Hex},
		{Data: []byte("你好，世界"), Expect: []byte("dbefd3ada018615b35588a01e216ae6e"), Encoding: encoding.Hex},
	}

	testHash(t, MD5, testCases)
}
