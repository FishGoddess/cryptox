// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/FishGoddess/cryptox/ed25519"
)

func main() {
	// Generate a key without seed.
	privateKey, publicKey, err := ed25519.GenerateKeys()
	if err != nil {
		panic(err)
	}

	// Generate a key with seed.
	seed := []byte("12345678876543211234567887654321")

	privateKey, publicKey, err = ed25519.GenerateKeys(ed25519.WithKeySeed(seed))
	if err != nil {
		panic(err)
	}

	// Store the private key and the public key to file.
	err = ed25519.StorePrivateKey("ed25519.key", privateKey)
	if err != nil {
		panic(err)
	}

	err = ed25519.StorePublicKey("ed25519.pub", publicKey)
	if err != nil {
		panic(err)
	}

	// Load the private key and the public key from file.
	privateKey, err = ed25519.LoadPrivateKey("ed25519.key")
	if err != nil {
		panic(err)
	}

	publicKey, err = ed25519.LoadPublicKey("ed25519.pub")
	if err != nil {
		panic(err)
	}
}
