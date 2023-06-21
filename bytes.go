// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

var (
	// FileFlag is the flag of file.
	FileFlag = os.O_CREATE | os.O_APPEND | os.O_WRONLY

	// FileMode is the mode of file.
	FileMode os.FileMode = 0644
)

var (
	// Base64 is the encoding of base64.
	Base64 = base64.StdEncoding
)

// Bytes is an alias of []byte.
type Bytes []byte

// Bytes returns Bytes in []byte.
func (bs Bytes) Bytes() []byte {
	return bs
}

// String returns Bytes in string.
func (bs Bytes) String() string {
	return string(bs)
}

// Hex returns Bytes in hex.
func (bs Bytes) Hex() string {
	return hex.EncodeToString(bs)
}

// Base64 returns Bytes in base64.
func (bs Bytes) Base64() string {
	return Base64.EncodeToString(bs)
}

// Clone clones bs to new slice.
func (bs Bytes) Clone() Bytes {
	newSlice := make([]byte, len(bs))
	copy(newSlice, bs)

	return newSlice
}

// newFile creates a new file of path.
func (bs Bytes) newFile(path string) (*os.File, error) {
	return os.OpenFile(path, FileFlag, FileMode)
}

// WriteTo writes bytes to writer.
func (bs Bytes) WriteTo(writer io.Writer) (n int64, err error) {
	nn, err := writer.Write(bs)
	return int64(nn), err
}

// WriteToFile writes bytes to file.
func (bs Bytes) WriteToFile(path string) (n int64, err error) {
	file, err := bs.newFile(path)
	if err != nil {
		return 0, err
	}

	defer file.Close()
	return bs.WriteTo(file)
}

// FromBytes creates a new Bytes from bs.
func FromBytes(bs []byte) Bytes {
	return bs
}

// FromString creates a new Bytes from string.
func FromString(str string) Bytes {
	return Bytes(str)
}

// FromHex creates a new Bytes from hex string.
func FromHex(hexString string) (Bytes, error) {
	return hex.DecodeString(hexString)
}

// FromBase64 creates a new Bytes from base64 string.
func FromBase64(base64String string) (Bytes, error) {
	return Base64.DecodeString(base64String)
}

// GenerateBytes generates a byte slice filled with random byte.
// It usually used to generate an iv and install iv to crypted data.
// For example, you use this method to generate a byte slice and pass it to encrypter as iv.
// After encrypting, you append this iv slice encoded to hex or base64 to crypted slice as they are one part.
// When you need to decrypt data, parse iv from the "crypted" slice including raw-crypted slice and iv slice first.
// Then you can pass this iv to decrypter and decrypt data as usual.
// However, you should know that the crypted data of the same plain data will be different every time because of different ivs.
func GenerateBytes(n int) (Bytes, error) {
	bs := make([]byte, n)

	read, err := rand.Read(bs)
	if err != nil {
		return nil, err
	}

	if read != n {
		return nil, fmt.Errorf("bytes: generate read %d != n %d", read, n)
	}

	return bs, nil
}
