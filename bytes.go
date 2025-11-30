// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"encoding/base64"
	"io"
	"os"
)

type Bytes []byte

// Base64 returns Bytes as base64.
func (bs Bytes) Base64() string {
	return base64.StdEncoding.EncodeToString(bs)
}

func (bs Bytes) newFile(path string) (*os.File, error) {
	flag := os.O_CREATE | os.O_EXCL | os.O_WRONLY
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
