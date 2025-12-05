// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package padding

import "fmt"

type Padding interface {
	// Pad pads some bytes to the byte slice.
	Pad(data []byte, blockSize int) []byte

	// Unpad unpads some bytes from the byte slice.
	Unpad(data []byte, blockSize int) ([]byte, error)
}

type None struct{}

// Pad returns the original byte slice.
func (None) Pad(data []byte, blockSize int) []byte {
	return data
}

// Unpad returns the original byte slice.
func (None) Unpad(data []byte, blockSize int) ([]byte, error) {
	return data, nil
}

type Zero struct{}

// Pad pads some bytes to the byte slice in zero way.
func (Zero) Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	for i := 0; i < padding; i++ {
		data = append(data, 0)
	}

	return data
}

// Unpad unpads some bytes from the byte slice in zero way.
func (Zero) Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)

	var i int
	for i = length; i > 0; i-- {
		if data[i-1] != 0 {
			break
		}

		// Remove block size of byte slice at most.
		if length-i >= blockSize {
			break
		}
	}

	return data[:i], nil
}

type PKCS5 struct{}

// Pad pads some bytes to the byte slice in pkcs5 way.
func (PKCS5) Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	for i := 0; i < padding; i++ {
		data = append(data, byte(padding))
	}

	return data
}

// Unpad unpads some bytes from the byte slice in pkcs5 way.
func (PKCS5) Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	number := int(data[length-1])

	if number > length {
		return nil, fmt.Errorf("cryptox/padding: unpad number %d > length %d", number, length)
	}

	if number > blockSize {
		return nil, fmt.Errorf("cryptox/padding: unpad number %d > blockSize %d", number, blockSize)
	}

	return data[:length-number], nil
}

type PKCS7 struct{}

// Pad pads some bytes to the byte slice in pkcs7 way.
func (PKCS7) Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	for i := 0; i < padding; i++ {
		data = append(data, byte(padding))
	}

	return data
}

// Unpad unpads some bytes from the byte slice in pkcs7 way.
func (PKCS7) Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	number := int(data[length-1])

	if number > length {
		return nil, fmt.Errorf("cryptox/padding: unpad number %d > length %d", number, length)
	}

	if number > blockSize {
		return nil, fmt.Errorf("cryptox/padding: unpad number %d > blockSize %d", number, blockSize)
	}

	return data[:length-number], nil
}
