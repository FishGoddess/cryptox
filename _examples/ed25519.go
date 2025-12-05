// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox/ed25519"
)

func main() {
	// Load the private key and the public key from file.
	// Check ed25519.Option for more information about file encoding.
	privateKey, err := ed25519.LoadPrivateKey("ed25519.key")
	if err != nil {
		panic(err)
	}

	publicKey, err := ed25519.LoadPublicKey("ed25519.pub")
	if err != nil {
		panic(err)
	}

	data := []byte("戴上头箍，爱不了你；不戴头箍，救不了你。")
	fmt.Printf("data: %s\n", data)

	// Use the private key to sign data.
	sign := privateKey.Sign(data, ed25519.WithHex())
	fmt.Printf("sign: %s\n", sign)

	// Use the public key to verify the sign.
	err = publicKey.Verify(data, sign, ed25519.WithHex())
	if err != nil {
		panic(err)
	}

	fmt.Printf("verify: %s\n", data)
}
