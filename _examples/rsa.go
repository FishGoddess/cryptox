// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox/rsa"
)

func main() {
	data := []byte("戴上头箍，爱不了你；不戴头箍，救不了你。")
	fmt.Printf("Data: %s\n", data)

	// Use public key to encrypt data.
	publicKey := rsa.MustLoadPublicKey("rsa.pub")
	_ = publicKey

	// Use private key to decrypt data.
	privateKey := rsa.MustLoadPrivateKey("rsa.pub")
	_ = privateKey
}
