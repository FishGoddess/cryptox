// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/hash"
	"github.com/FishGoddess/cryptox/rsa"
)

func main() {
	// Load the private key and the public key from file.
	privateKey, err := rsa.LoadPrivateKey("rsa.key")
	if err != nil {
		panic(err)
	}

	publicKey, err := rsa.LoadPublicKey("rsa.pub")
	if err != nil {
		panic(err)
	}

	msg := []byte("戴上头箍，爱不了你；不戴头箍，救不了你。")
	fmt.Printf("msg: %s\n", msg)

	// Use the public key to encrypt msg using base64 encoding.
	label := []byte("你好，世界")

	encrypt, err := publicKey.EncryptOAEP(msg, label, encoding.Base64)
	if err != nil {
		panic(err)
	}

	fmt.Printf("encrypt: %s\n", encrypt)

	// Use the private key to decrypt msg using base64 encoding.
	decrypt, err := privateKey.DecryptOAEP(encrypt, label, encoding.Base64)
	if err != nil {
		panic(err)
	}

	fmt.Printf("decrypt: %s\n", decrypt)

	// Use the private key to sign msg.
	digest := hash.SHA256(msg, encoding.Hex)

	sign, err := privateKey.SignPSS(digest, 0, encoding.Hex)
	if err != nil {
		panic(err)
	}

	fmt.Printf("sign: %s\n", sign)

	// Use the public key to verify the sign.
	err = publicKey.VerifyPSS(digest, sign, 0, encoding.Hex)
	if err != nil {
		panic(err)
	}

	fmt.Println("verify: %s\n", digest)
}
