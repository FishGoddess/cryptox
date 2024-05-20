// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
)

type Bytes []byte

// ParseHex a hex string to bytes.
func ParseHex(hexString string) (Bytes, error) {
	return hex.DecodeString(hexString)
}

// ParseBase64 a base64 string to bytes.
func ParseBase64(base64String string) (Bytes, error) {
	return base64.StdEncoding.DecodeString(base64String)
}

// Hex returns Bytes as hex.
func (bs Bytes) Hex() string {
	return hex.EncodeToString(bs)
}

// Base64 returns Bytes as base64.
func (bs Bytes) Base64() string {
	return base64.StdEncoding.EncodeToString(bs)
}

// Clone clones bs and returns a new slice.
func (bs Bytes) Clone() Bytes {
	newSlice := make([]byte, len(bs))
	copy(newSlice, bs)

	return newSlice
}

func (bs Bytes) newFile(path string) (*os.File, error) {
	flag := os.O_CREATE | os.O_APPEND | os.O_WRONLY
	mode := os.FileMode(0644)

	return os.OpenFile(path, flag, mode)
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
