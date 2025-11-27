// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rand

import (
	"math/rand/v2"
	"unsafe"
)

var words = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func appendBytes(bs []byte, n int) []byte {
	length := len(words)
	for i := 0; i < n; i++ {
		index := rand.IntN(length)
		bs = append(bs, words[index])
	}

	return bs
}

// Bytes returns n bytes in random which can be used to generate an iv.
func Bytes(n int) []byte {
	bs := make([]byte, 0, n)
	bs = appendBytes(bs, n)
	return bs
}

// String returns a string including n bytes in random which can be used to generate an iv.
func String(n int) string {
	bs := Bytes(n)
	ptr := unsafe.SliceData(bs)
	return unsafe.String(ptr, len(bs))
}
