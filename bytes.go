// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"crypto/rand"
	"fmt"
)

// copyBytes copies bs to a new byte slice.
func copyBytes(bs []byte) []byte {
	newSlice := make([]byte, len(bs))
	copy(newSlice, bs)

	return newSlice
}

// RandomBytes returns a byte slice filled with random byte.
// It usually used to generate an iv and install iv to crypted data.
// For example, you use this method to generate a byte slice and pass it to encrypter as iv.
// After encrypting, you append this iv slice encoded to hex or base64 to crypted slice as they are one part.
// When you need to decrypt data, parse iv from the "crypted" slice including raw-crypted slice and iv slice first.
// Then you can pass this iv to decrypter and decrypt data as usual.
// However, you should know that the crypted data of the same plain data will be different every time because of different ivs.
func RandomBytes(n int) ([]byte, error) {
	bs := make([]byte, n)

	read, err := rand.Read(bs)
	if err != nil {
		return nil, err
	}

	if read != n {
		return nil, fmt.Errorf("cryptox.RandomBytes: read %d != n %d", read, n)
	}

	return bs, nil
}
