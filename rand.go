// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"math/rand"
	"time"
	"unsafe"
)

const words = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var source = rand.NewSource(time.Now().UnixNano())

// AppendBytes appends n random bytes to bs.
func AppendBytes(bs Bytes, n int) Bytes {
	length := int64(len(words))

	for i := 0; i < n; i++ {
		index := source.Int63() % length
		bs = append(bs, words[index])
	}

	return bs
}

// GenerateBytes generates n random bytes and returns them.
// It usually used to generate an iv and store it to an safe database.
// It means each encrypted data has an different iv so your encrypted data is safer than using a fixed iv.
// However, you should know that the encrypted data of same data will be different if the iv is different.
func GenerateBytes(n int) Bytes {
	bs := make(Bytes, 0, n)
	bs = AppendBytes(bs, n)

	return bs
}

// GenerateString generates a string including n random bytes and returns it.
func GenerateString(n int) string {
	bs := GenerateBytes(n)
	bsPtr := unsafe.SliceData(bs)

	return unsafe.String(bsPtr, len(bs))
}
