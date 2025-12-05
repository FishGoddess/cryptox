// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"

	"github.com/FishGoddess/cryptox/des"
)

func main() {
	// As you know, key is necessary in des.
	// However, not all modes need iv, such as ecb.
	key := []byte("12345678")
	iv := []byte("87654321")

	data := []byte("你好，世界")
	fmt.Printf("data: %s\n", data)

	// Use ctr mode to encrypt data with no padding and encoding base64.
	encrypt, err := des.EncryptCTR(data, key, iv, des.WithBase64())
	if err != nil {
		panic(err)
	}

	fmt.Printf("encrypt: %s\n", encrypt)

	// Decrypt data in the same way.
	decrypt, err := des.DecryptCTR(encrypt, key, iv, des.WithBase64())
	if err != nil {
		panic(err)
	}

	fmt.Printf("decrypt: %s\n", decrypt)
	fmt.Printf("decrypt is right: %+v\n", bytes.Equal(decrypt, data))
}
