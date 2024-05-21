// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"

	"github.com/FishGoddess/cryptox"
	"github.com/FishGoddess/cryptox/des"
)

func main() {
	// As you know, key is necessary in triple des.
	// However, not all modes need iv, such as ecb.
	key := []byte("123456788765432112345678")
	iv := []byte("87654321")

	msg := []byte("你好，世界")
	fmt.Printf("msg: %s\n", msg)

	// We use ctr mode and no padding to encrypt data.
	// Of course, you can choose another mode if you want.
	// Also, you can choose no/zero/pkcs5/pkcs7 to padding data.
	encrypted, err := des.EncryptCTRTriple(key, iv, cryptox.PaddingNone, msg)
	if err != nil {
		panic(err)
	}

	fmt.Println("encrypted:", encrypted)
	fmt.Println("encrypted hex:", encrypted.Hex())
	fmt.Println("encrypted base64:", encrypted.Base64())

	// We use ctr mode and no padding to decrypt data.
	// Of course, you can choose another mode if you want.
	// Also, you can choose no/zero/pkcs5/pkcs7 to undo padding data.
	decrypted, err := des.DecryptCTRTriple(key, iv, cryptox.PaddingNone, encrypted)
	if err != nil {
		panic(err)
	}

	fmt.Printf("decrypted: %s\n", decrypted)
	fmt.Println("decrypted == msg", bytes.Equal(decrypted, msg))
}
