// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rand

import (
	"math/rand"
	"time"
	"unsafe"
)

const words = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var source = rand.NewSource(time.Now().UnixNano())

// AppendBytes appends n random bytes to bs.
func AppendBytes(bs []byte, n int) []byte {
	length := int64(len(words))
	for i := 0; i < n; i++ {
		index := source.Int63() % length
		bs = append(bs, words[index])
	}

	return bs
}

// Bytes generates n random bytes, and it usually used to generate an iv.
// It means each encrypted data has an different iv so your encrypted data is safer than using a fixed iv.
// However, you should know that the encrypted data of same data will be different if the iv is different.
func Bytes(n int) []byte {
	bs := make([]byte, 0, n)
	bs = AppendBytes(bs, n)
	return bs
}

// String generates a string including n random bytes.
func String(n int) string {
	bs := Bytes(n)
	ptr := unsafe.SliceData(bs)
	return unsafe.String(ptr, len(bs))
}
