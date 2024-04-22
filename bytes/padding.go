// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package bytes

import "fmt"

type Padding interface {
	Padding(bs []byte, blockSize int) []byte
	UndoPadding(bs []byte, blockSize int) ([]byte, error)
}

// PaddingNone won't padding anything to bs.
func PaddingNone() Padding {
	return paddingNone{}
}

// PaddingZero paddings zero to bs.
func PaddingZero() Padding {
	return paddingZero{}
}

// PaddingPKCS5 paddings bs using pkcs5.
func PaddingPKCS5() Padding {
	return paddingPKCS7{}
}

// PaddingPKCS7 paddings bs using pkcs7.
func PaddingPKCS7() Padding {
	return paddingPKCS7{}
}

type paddingNone struct{}

func (paddingNone) Padding(bs []byte, blockSize int) []byte {
	return bs
}

func (paddingNone) UndoPadding(bs []byte, blockSize int) ([]byte, error) {
	return bs, nil
}

type paddingZero struct{}

func (paddingZero) Padding(bs []byte, blockSize int) []byte {
	padding := blockSize - (len(bs) % blockSize)

	for i := 0; i < padding; i++ {
		bs = append(bs, 0)
	}

	return bs
}

func (paddingZero) UndoPadding(bs []byte, blockSize int) ([]byte, error) {
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

type paddingPKCS7 struct{}

func (paddingPKCS7) Padding(bs []byte, blockSize int) []byte {
	padding := blockSize - (len(bs) % blockSize)

	for i := 0; i < padding; i++ {
		bs = append(bs, byte(padding))
	}

	return bs
}

func (paddingPKCS7) UndoPadding(bs []byte, blockSize int) ([]byte, error) {
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
