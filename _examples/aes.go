// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"

	"github.com/FishGoddess/cryptox/aes"
	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/bytes/padding"
)

func main() {
	// As you know, key is necessary in aes.
	// However, not all modes need iv, such as ecb.
	key := []byte("12345678876543211234567887654321")
	iv := []byte("8765432112345678")

	msg := []byte("你好，世界")
	fmt.Printf("msg: %s\n", msg)

	// Use ctr mode to encrypt data with no padding and encoding base64.
	encrypt, err := aes.EncryptCTR(msg, key, iv, padding.None, encoding.Base64)
	if err != nil {
		panic(err)
	}

	fmt.Printf("encrypt: %s\n", encrypt)

	// Decrypt data in the same way.
	decrypt, err := aes.DecryptCTR(encrypt, key, iv, padding.None, encoding.Base64)
	if err != nil {
		panic(err)
	}

	fmt.Printf("decrypt: %s\n", decrypt)
	fmt.Printf("decrypt is right: %+v\n", bytes.Equal(decrypt, msg))
}
