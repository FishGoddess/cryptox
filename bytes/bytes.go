// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package bytes

import (
	"os"
)

var (
	FileFlag             = os.O_CREATE | os.O_APPEND | os.O_WRONLY
	FileMode os.FileMode = 0644
)

// Copy copies all bytes in bs to a new slice and returns it.
func Copy(bs []byte) []byte {
	result := make([]byte, len(bs))
	copy(result, bs)

	return result
}

// WriteFile writes bs to a file.
// It returns the bytes written or an error if failed.
func WriteFile(filename string, bs []byte) (n int, err error) {
	file, err := os.OpenFile(filename, FileFlag, FileMode)
	if err != nil {
		return 0, err
	}

	defer file.Close()
	return file.Write(bs)
}
