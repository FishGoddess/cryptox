// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import "fmt"

var (
	PaddingNone  Padding = paddingNone{}
	PaddingZero  Padding = paddingZero{}
	PaddingPKCS5 Padding = paddingPKCS7{} // PKCS5 is actually the same as pkcs7.
	PaddingPKCS7 Padding = paddingPKCS7{}
)

// Padding paddings and undo paddings to a byte slice.
// You should know the returned bytes is always cloned from the passed bytes,
// so they are two different byte slices.
type Padding interface {
	Padding(bs Bytes, blockSize int) Bytes
	UndoPadding(bs Bytes, blockSize int) (Bytes, error)
}

type paddingNone struct{}

func (paddingNone) Padding(bs Bytes, blockSize int) Bytes {
	return bs.Clone()
}

func (paddingNone) UndoPadding(bs Bytes, blockSize int) (Bytes, error) {
	return bs.Clone(), nil
}

type paddingZero struct{}

func (paddingZero) Padding(bs Bytes, blockSize int) Bytes {
	bs = bs.Clone()
	padding := blockSize - (len(bs) % blockSize)

	for i := 0; i < padding; i++ {
		bs = append(bs, 0)
	}

	return bs
}

func (paddingZero) UndoPadding(bs Bytes, blockSize int) (Bytes, error) {
	bs = bs.Clone()
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

func (paddingPKCS7) Padding(bs Bytes, blockSize int) Bytes {
	bs = bs.Clone()
	padding := blockSize - (len(bs) % blockSize)

	for i := 0; i < padding; i++ {
		bs = append(bs, byte(padding))
	}

	return bs
}

func (paddingPKCS7) UndoPadding(bs Bytes, blockSize int) (Bytes, error) {
	bs = bs.Clone()
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
