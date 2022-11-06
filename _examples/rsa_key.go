// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox/rsa"
)

func main() {
	// Generate a 2048 bits key.
	// More encoder/decoder information in rsa.KeyOption.
	privateKey, publicKey, err := rsa.GenerateKeys(2048)
	if err != nil {
		panic(err)
	}

	fmt.Println(privateKey)
	fmt.Println(publicKey)

	// Try WriteToFile if you want to write your private key to file.
	n, err := privateKey.Bytes().WriteToFile("rsa.key")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Write %d bytes to private key file\n", n)

	// Try WriteToFile if you want to write your public key to file.
	n, err = publicKey.Bytes().WriteToFile("rsa.pub")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Write %d bytes to public key file\n", n)

	// Load private key from file.
	loadedPrivateKey, err := rsa.LoadPrivateKey("rsa.key")
	if err != nil {
		panic(err)
	}

	// Load public key from file.
	loadedPublicKey, err := rsa.LoadPublicKey("rsa.pub")
	if err != nil {
		panic(err)
	}

	fmt.Println(loadedPrivateKey)
	fmt.Println(loadedPublicKey)

	// Already have a private key in bytes?
	// Try these:
	_, _ = rsa.ParsePrivateKey(privateKey.Bytes())
	_, _ = rsa.ParsePublicKey(publicKey.Bytes())

	// Want to load keys from file and panic if failed?
	// Try these:
	_ = rsa.MustLoadPrivateKey("rsa.key")
	_ = rsa.MustLoadPublicKey("rsa.pub")
}
