// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package padding

import "fmt"

type Padding interface {
	// Pad pads some bytes to the byte slice.
	Pad(bs []byte, blockSize int) []byte

	// Unpad unpads some bytes from the byte slice.
	Unpad(bs []byte, blockSize int) ([]byte, error)
}

type None struct{}

// Pad returns the original byte slice.
func (None) Pad(bs []byte, blockSize int) []byte {
	return bs
}

// Unpad returns the original byte slice.
func (None) Unpad(bs []byte, blockSize int) ([]byte, error) {
	return bs, nil
}

type Zero struct{}

// Pad pads some bytes to the byte slice in zero way.
func (Zero) Pad(bs []byte, blockSize int) []byte {
	padding := blockSize - (len(bs) % blockSize)
	for i := 0; i < padding; i++ {
		bs = append(bs, 0)
	}

	return bs
}

// Unpad unpads some bytes from the byte slice in zero way.
func (Zero) Unpad(bs []byte, blockSize int) ([]byte, error) {
	length := len(bs)

	var i int
	for i = length; i > 0; i-- {
		if bs[i-1] != 0 {
			break
		}

		// Remove block size of byte slice at most.
		if length-i >= blockSize {
			break
		}
	}

	return bs[:i], nil
}

type PKCS5 struct{}

// Pad pads some bytes to the byte slice in pkcs5 way.
func (PKCS5) Pad(bs []byte, blockSize int) []byte {
	padding := blockSize - (len(bs) % blockSize)
	for i := 0; i < padding; i++ {
		bs = append(bs, byte(padding))
	}

	return bs
}

// Unpad unpads some bytes from the byte slice in pkcs5 way.
func (PKCS5) Unpad(bs []byte, blockSize int) ([]byte, error) {
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

type PKCS7 struct{}

// Pad pads some bytes to the byte slice in pkcs7 way.
func (PKCS7) Pad(bs []byte, blockSize int) []byte {
	padding := blockSize - (len(bs) % blockSize)
	for i := 0; i < padding; i++ {
		bs = append(bs, byte(padding))
	}

	return bs
}

// Unpad unpads some bytes from the byte slice in pkcs7 way.
func (PKCS7) Unpad(bs []byte, blockSize int) ([]byte, error) {
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
