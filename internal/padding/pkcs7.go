// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package padding

import "fmt"

type paddingPKCS7 struct{}

func (paddingPKCS7) Pad(bs []byte, blockSize int) []byte {
	padding := blockSize - (len(bs) % blockSize)
	for i := 0; i < padding; i++ {
		bs = append(bs, byte(padding))
	}

	return bs
}

func (paddingPKCS7) Unpad(bs []byte, blockSize int) ([]byte, error) {
	length := len(bs)
	number := int(bs[length-1])

	if number > length {
		return nil, fmt.Errorf("cryptox: unpad number %d > length %d", number, length)
	}

	if number > blockSize {
		return nil, fmt.Errorf("cryptox: unpad number %d > blockSize %d", number, blockSize)
	}

	return bs[:length-number], nil
}
