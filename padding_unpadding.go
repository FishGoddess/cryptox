// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"fmt"
)

var (
	_ Padding = PaddingNone
	_ Padding = PaddingZero
	_ Padding = PaddingPKCS5
	_ Padding = PaddingPKCS7
)

var (
	_ UnPadding = UnPaddingNone
	_ UnPadding = UnPaddingZero
	_ UnPadding = UnPaddingPKCS5
	_ UnPadding = UnPaddingPKCS7
)

// Padding paddings bs with blockSize.
type Padding func(bs Bytes, blockSize int) Bytes

// UnPadding unPaddings bs with blockSize.
type UnPadding func(bs Bytes, blockSize int) (Bytes, error)

// PaddingNone won't padding anything to bs.
func PaddingNone(bs Bytes, blockSize int) Bytes {
	return bs
}

// PaddingZero paddings zero to bs.
func PaddingZero(bs Bytes, blockSize int) Bytes {
	padding := blockSize - (len(bs) % blockSize)

	for i := 0; i < padding; i++ {
		bs = append(bs, 0)
	}

	return bs
}

// PaddingPKCS5 paddings bs using pkcs5.
func PaddingPKCS5(bs Bytes, blockSize int) Bytes {
	return PaddingPKCS7(bs, blockSize)
}

// PaddingPKCS7 paddings bs using pkcs7.
func PaddingPKCS7(bs Bytes, blockSize int) Bytes {
	padding := blockSize - (len(bs) % blockSize)

	for i := 0; i < padding; i++ {
		bs = append(bs, byte(padding))
	}

	return bs
}

// UnPaddingNone won't unPadding anything from bs.
func UnPaddingNone(bs Bytes, blockSize int) (Bytes, error) {
	return bs, nil
}

// UnPaddingZero unPaddings zero from bs.
func UnPaddingZero(bs Bytes, blockSize int) (Bytes, error) {
	length := len(bs)

	var i int
	for i = length; i > 0; i-- {
		if bs[i-1] != 0 {
			break
		}

		// Remove blockSize of bytes at most due to padding blockSize of bytes at most.
		if length-i >= blockSize {
			break
		}
	}

	return bs[:i], nil
}

// UnPaddingPKCS5 unPaddings bs using pkcs5.
func UnPaddingPKCS5(bs Bytes, blockSize int) (Bytes, error) {
	return UnPaddingPKCS7(bs, blockSize)
}

// UnPaddingPKCS7 unPaddings bs using pkcs7.
func UnPaddingPKCS7(bs Bytes, blockSize int) (Bytes, error) {
	length := len(bs)
	number := int(bs[length-1])

	if number > length {
		return nil, fmt.Errorf("cryptox: unpadding pkcs7 number %d > length %d", number, length)
	}

	if number > blockSize {
		return nil, fmt.Errorf("cryptox: unpadding pkcs7 number %d > blockSize %d", number, blockSize)
	}

	return bs[:length-number], nil
}
