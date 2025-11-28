// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"

	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/bytes/padding"
	"github.com/FishGoddess/cryptox/des"
)

func main() {
	// As you know, key is necessary in des.
	// However, not all modes need iv, such as ecb.
	key := []byte("12345678")
	iv := []byte("87654321")

	msg := []byte("你好，世界")
	fmt.Printf("msg: %s\n", msg)

	// For example, we can use ctr mode and no padding to encrypt data.
	encrypt, err := des.EncryptCTR(msg, key, iv, padding.PaddingNone, encoding.None)
	if err != nil {
		panic(err)
	}

	// Use encoding to output hex bytes.
	encryptHex, err := des.EncryptCTR(msg, key, iv, padding.PaddingNone, encoding.Hex)
	if err != nil {
		panic(err)
	}

	// Use encoding to output base64 bytes.
	encryptBase64, err := des.EncryptCTR(msg, key, iv, padding.PaddingNone, encoding.Base64)
	if err != nil {
		panic(err)
	}

	fmt.Printf("encrypt: %+v\n", encrypt)
	fmt.Printf("encrypt hex: %s", encryptHex)
	fmt.Printf("encrypt base64: %s", encryptBase64)

	// We use ctr mode and no padding to decrypt data.
	decrypt, err := des.DecryptCTR(encrypt, key, iv, padding.PaddingNone, encoding.None)
	if err != nil {
		panic(err)
	}

	// Use encoding to input hex bytes.
	decryptHex, err := des.DecryptCTR(encryptHex, key, iv, padding.PaddingNone, encoding.Hex)
	if err != nil {
		panic(err)
	}

	// Use encoding to input base64 bytes..
	decryptBase64, err := des.DecryptCTR(encryptBase64, key, iv, padding.PaddingNone, encoding.Base64)
	if err != nil {
		panic(err)
	}

	fmt.Printf("decrypt: %s\n", decrypt)
	fmt.Printf("decrypt hex: %s\n", decryptHex)
	fmt.Printf("decrypt base64: %s\n", decryptBase64)
	fmt.Println("decrypt is right: %+v", bytes.Equal(decrypt, msg))
}
