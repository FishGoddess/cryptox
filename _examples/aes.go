// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox"
	"github.com/FishGoddess/cryptox/aes"
)

func main() {
	// As you know, key is necessary in aes.
	// However, not all modes need iv, such as ecb.
	key := cryptox.FromString("12345678876543211234567887654321")
	iv := cryptox.FromString("8765432112345678")

	plain := cryptox.FromString("你好，世界")
	fmt.Println("plain:", plain)

	// We use ctr mode and no padding to encrypt data.
	// Of course, you can choose ecb/cbc/cfb/ofb/ctr if you want.
	// Also, you can choose no/zero/pkcs5/pkcs7 to padding data.
	crypted, err := aes.New(key).EncryptCTR(cryptox.PaddingNone, iv, plain)
	if err != nil {
		panic(err)
	}

	fmt.Println("crypted:", crypted)
	fmt.Println("cryptedHex:", crypted.Hex())
	fmt.Println("cryptedBase64:", crypted.Base64())

	// We use ctr mode and no unPadding to decrypt data.
	// Of course, you can choose ecb/cbc/cfb/ofb/ctr if you want.
	// Also, you can choose no/zero/pkcs5/pkcs7 to unPadding data.
	newPlain, err := aes.New(key).DecryptCTR(cryptox.UnPaddingNone, iv, crypted)
	if err != nil {
		panic(err)
	}

	fmt.Println("newPlain:", newPlain)
	fmt.Println("newPlain == plain", newPlain.String() == plain.String())
}
