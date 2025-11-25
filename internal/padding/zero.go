// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package padding

type paddingZero struct{}

func (paddingZero) Pad(bs []byte, blockSize int) []byte {
	padding := blockSize - (len(bs) % blockSize)
	for i := 0; i < padding; i++ {
		bs = append(bs, 0)
	}

	return bs
}

func (paddingZero) Unpad(bs []byte, blockSize int) ([]byte, error) {
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
