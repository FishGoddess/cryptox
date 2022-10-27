package crypto

import (
	"fmt"
)

type Padder interface {
	Padding(data []byte, blockSize int) []byte
	UnPadding(data []byte, blockSize int) ([]byte, error)
}

// PKCS5 uses pkcs7 to padding and unPadding a byte slice.
// The original pkcs5 has the fixed block size 8 which doesn't feat with the bigger block size.
// So we recommend you to use pkcs7 instead.
func PKCS5() Padder {
	return pkcs7{}
}

// PKCS7 uses pkcs7 to padding and unPadding a byte slice.
func PKCS7() Padder {
	return pkcs7{}
}

// ZeroPadding uses zero byte to padding and unPadding a byte slice.
func ZeroPadding() Padder {
	return zero{}
}

type pkcs7 struct{}

func (pkcs7) Padding(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)

	for i := 0; i < padding; i++ {
		data = append(data, byte(padding))
	}

	return data
}

func (pkcs7) UnPadding(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	number := int(data[length-1])

	if number > length || number > blockSize {
		return nil, fmt.Errorf("cryptox.pkcs7: invalid number %d", number)
	}

	return data[:length-number], nil
}

type zero struct{}

func (zero) Padding(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)

	for i := 0; i < padding; i++ {
		data = append(data, 0)
	}

	return data
}

func (zero) UnPadding(data []byte, blockSize int) ([]byte, error) {
	length := len(data)

	var i int
	for i = length - 1; i >= 0; i-- {
		if data[i] != 0 {
			break
		}
	}

	return data[:i+1], nil
}
