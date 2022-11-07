// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox/rsa"
)

var (
	// Use public key to encrypt msg.
	publicKey = rsa.MustLoadPublicKey("rsa.pub")

	// Use private key to decrypt msg.
	privateKey = rsa.MustLoadPrivateKey("rsa.key")
)

func main() {
	msg := []byte("戴上头箍，爱不了你；不戴头箍，救不了你。")
	fmt.Printf("Msg: %s\n", msg)

	encrypted, err := publicKey.EncryptPKCS1v15(msg)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Encrypted: %s\n", encrypted.Base64())

	decrypted, err := privateKey.DecryptPKCS1v15(encrypted)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted: %s\n", decrypted)
}
