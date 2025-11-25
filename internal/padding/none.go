// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package padding

type paddingNone struct{}

func (paddingNone) Pad(bs []byte, blockSize int) []byte {
	return bs
}

func (paddingNone) Unpad(bs []byte, blockSize int) ([]byte, error) {
	return bs, nil
}
