// Copyright 2022 FishGoddess. All rights reserved.
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

// Padding paddings data with blockSize.
type Padding func(data []byte, blockSize int) []byte

// UnPadding unPaddings data with blockSize.
type UnPadding func(data []byte, blockSize int) ([]byte, error)

// PaddingNone won't padding anything to data.
func PaddingNone(data []byte, _ int) []byte {
	return data
}

// UnPaddingNone won't unPadding anything from data.
func UnPaddingNone(data []byte, _ int) ([]byte, error) {
	return data, nil
}

// PaddingZero paddings zero to data.
func PaddingZero(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)

	for i := 0; i < padding; i++ {
		data = append(data, 0)
	}

	return data
}

// UnPaddingZero unPaddings zero from data.
func UnPaddingZero(data []byte, blockSize int) ([]byte, error) {
	length := len(data)

	var i int
	for i = length; i > 0; i-- {
		if data[i-1] != 0 {
			break
		}

		// Remove blockSize of bytes at most due to padding blockSize of bytes at most.
		if length-i >= blockSize {
			break
		}
	}

	return data[:i], nil
}

// PaddingPKCS5 paddings data using pkcs5.
func PaddingPKCS5(data []byte, blockSize int) []byte {
	return PaddingPKCS7(data, blockSize)
}

// UnPaddingPKCS5 unPaddings data using pkcs5.
func UnPaddingPKCS5(data []byte, blockSize int) ([]byte, error) {
	return UnPaddingPKCS7(data, blockSize)
}

// PaddingPKCS7 paddings data using pkcs7.
func PaddingPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)

	for i := 0; i < padding; i++ {
		data = append(data, byte(padding))
	}

	return data
}

// UnPaddingPKCS7 unPaddings data using pkcs7.
func UnPaddingPKCS7(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	number := int(data[length-1])

	if number > length || number > blockSize {
		return nil, fmt.Errorf("cryptox.UnPaddingPKCS7: number %d > length %d || number %d > blockSize %d", number, length, number, blockSize)
	}

	return data[:length-number], nil
}
