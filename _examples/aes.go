// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"

	"github.com/FishGoddess/cryptox/aes"
	"github.com/FishGoddess/cryptox/bytes/encoding"
)

func main() {
	// As you know, key is necessary in aes.
	// However, not all modes need iv, such as ecb.
	key := []byte("12345678876543211234567887654321")
	nonce := []byte("123456abcdef")

	msg := []byte("你好，世界")
	fmt.Printf("msg: %s\n", msg)

	// Use gcm mode to encrypt data with no padding and encoding base64.
	encrypt, err := aes.EncryptGCM(msg, key, nonce, nil, encoding.Base64)
	if err != nil {
		panic(err)
	}

	fmt.Printf("encrypt: %s\n", encrypt)

	// Decrypt data in the same way.
	decrypt, err := aes.DecryptGCM(encrypt, key, nonce, nil, encoding.Base64)
	if err != nil {
		panic(err)
	}

	fmt.Printf("decrypt: %s\n", decrypt)
	fmt.Printf("decrypt is right: %+v\n", bytes.Equal(decrypt, msg))
}
