// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox"
	"github.com/FishGoddess/cryptox/des"
)

func main() {
	// As you know, key is necessary in 3des.
	// However, not all modes need iv, such as ecb.
	key := []byte("123456788765432112345678")
	iv := []byte("87654321")

	plain := []byte("你好，世界")
	fmt.Println("plain:", plain)

	// We use cbc mode and pkcs7 padding to encrypt data.
	// Of course, you can choose ecb/cbc/cfb/ofb/ctr if you want.
	// Also, you can choose no/zero/pkcs5/pkcs7 to padding data.
	crypted, err := des.NewTriple(key).EncryptCTR(cryptox.PaddingPKCS7, iv, plain)
	if err != nil {
		panic(err)
	}

	fmt.Println("crypted:", crypted)
	fmt.Println("cryptedHex:", crypted.Hex())
	fmt.Println("cryptedBase64:", crypted.Base64())

	// We use cbc mode and pkcs7 unPadding to decrypt data.
	// Of course, you can choose ecb/cbc/cfb/ofb/ctr if you want.
	// Also, you can choose no/zero/pkcs5/pkcs7 to unPadding data.
	newPlain, err := des.NewTriple(key).DecryptCTR(cryptox.UnPaddingNone, iv, crypted)
	if err != nil {
		panic(err)
	}

	fmt.Println("newPlain:", newPlain)
	fmt.Println("newPlain == plain", newPlain.String() == plain.String())
}
