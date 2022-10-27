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

type Padding func(data []byte, blockSize int) []byte

type UnPadding func(data []byte, blockSize int) ([]byte, error)

func PaddingNone(data []byte, blockSize int) []byte {
	return data
}

func UnPaddingNone(data []byte, blockSize int) ([]byte, error) {
	return data, nil
}

func PaddingZero(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)

	for i := 0; i < padding; i++ {
		data = append(data, 0)
	}

	return data
}

func UnPaddingZero(data []byte, blockSize int) ([]byte, error) {
	length := len(data)

	var i int
	for i = length - 1; i >= 0; i-- {
		if data[i] != 0 {
			break
		}
	}

	return data[:i+1], nil
}

func PaddingPKCS5(data []byte, blockSize int) []byte {
	return PaddingPKCS7(data, blockSize)
}

func UnPaddingPKCS5(data []byte, blockSize int) ([]byte, error) {
	return UnPaddingPKCS7(data, blockSize)
}

func PaddingPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)

	for i := 0; i < padding; i++ {
		data = append(data, byte(padding))
	}

	return data
}

func UnPaddingPKCS7(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	number := int(data[length-1])

	if number > length || number > blockSize {
		return nil, fmt.Errorf("cryptox.UnPaddingPKCS7: number %d > length %d || number %d > blockSize %d", number, length, number, blockSize)
	}

	return data[:length-number], nil
}
