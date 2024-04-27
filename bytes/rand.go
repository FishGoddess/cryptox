// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package bytes

import (
	"math/rand"
	"time"
	"unsafe"
)

const words = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var source = rand.NewSource(time.Now().UnixNano())

// AppendRandomBytes appends n random bytes to bs.
func AppendRandomBytes(bs []byte, n int) []byte {
	length := int64(len(words))

	for i := 0; i < n; i++ {
		index := source.Int63() % length
		bs = append(bs, words[index])
	}

	return bs
}

// GenerateBytes generates n random bytes and returns them.
func GenerateBytes(n int) []byte {
	bs := make([]byte, 0, n)
	bs = AppendRandomBytes(bs, n)

	return bs
}

// GenerateString generates a random string and returns it.
func GenerateString(n int) string {
	bs := GenerateBytes(n)

	// See strings.Builder.String().
	return *(*string)(unsafe.Pointer(&bs))
}
