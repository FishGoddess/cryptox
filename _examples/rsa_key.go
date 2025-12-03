// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/FishGoddess/cryptox/rsa"
)

func main() {
	// Generate a 2048 bits key.
	privateKey, publicKey, err := rsa.GenerateKeys(2048)
	if err != nil {
		panic(err)
	}

	// Store the private key and the public key to file.
	err = rsa.StorePrivateKey("rsa.key", privateKey)
	if err != nil {
		panic(err)
	}

	err = rsa.StorePublicKey("rsa.pub", publicKey)
	if err != nil {
		panic(err)
	}

	// Load the private key and the public key from file.
	privateKey, err = rsa.LoadPrivateKey("rsa.key")
	if err != nil {
		panic(err)
	}

	publicKey, err = rsa.LoadPublicKey("rsa.pub")
	if err != nil {
		panic(err)
	}
}
