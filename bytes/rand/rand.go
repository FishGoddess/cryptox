// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rand

import (
	crand "crypto/rand"
	"io"
	mrand "math/rand/v2"
	"unsafe"
)

var words = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func readFull(data []byte, n int) []byte {
	for i := 0; i < n && i < len(data); i++ {
		index := mrand.IntN(len(words))
		data[i] = words[index]
	}

	return data
}

// Bytes returns n bytes in random which can be used to generate an iv.
func Bytes(n int, opts ...Option) []byte {
	conf := newConfig().Apply(opts...)

	data := make([]byte, n)
	if conf.weak {
		readFull(data, n)
	} else {
		io.ReadFull(crand.Reader, data)
	}

	return data
}

// String returns a string including n bytes in random which can be used to generate an iv.
func String(n int, opts ...Option) string {
	data := Bytes(n, opts...)
	ptr := unsafe.SliceData(data)
	return unsafe.String(ptr, len(data))
}
