// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"

	"github.com/FishGoddess/cryptox"
)

const (
	blockTypePublic  = "RSA Public Key"
	blockTypePrivate = "RSA Private Key"
)

var (
	// KeyFileFlag is the flag of key file.
	KeyFileFlag = os.O_CREATE | os.O_APPEND | os.O_WRONLY

	// KeyFileMode is the mode of key file.
	KeyFileMode os.FileMode = 0644
)

// Key stores public key and private key of rsa.
type Key struct {
	Public  cryptox.Bytes
	Private cryptox.Bytes
}

// newFile creates a new file of path.
func (k Key) newFile(path string) (*os.File, error) {
	return os.OpenFile(path, KeyFileFlag, KeyFileMode)
}

// WriteTo writes public key and private key to writer.
func (k Key) WriteTo(publicWriter io.Writer, privateWriter io.Writer) (n int, err error) {
	n, err = publicWriter.Write(k.Public)
	if err != nil {
		return n, err
	}

	nn, err := privateWriter.Write(k.Private)
	if err != nil {
		return n + nn, err
	}

	return n + nn, nil
}

// WriteToFile writes public key and private key to file.
func (k Key) WriteToFile(publicPath string, privatePath string) (n int, err error) {
	publicFile, err := k.newFile(publicPath)
	if err != nil {
		return 0, err
	}

	defer publicFile.Close()

	privateFile, err := k.newFile(privatePath)
	if err != nil {
		return 0, err
	}

	defer privateFile.Close()

	return k.WriteTo(publicFile, privateFile)
}

// GenerateKey generates a key set of bits.
func GenerateKey(bits int) (Key, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return Key{}, err
	}

	privateKeyBlock := &pem.Block{
		Type:  blockTypePrivate,
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	var privateKeyPem bytes.Buffer
	if err = pem.Encode(&privateKeyPem, privateKeyBlock); err != nil {
		return Key{}, err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return Key{}, err
	}

	publicKeyBlock := &pem.Block{
		Type:  blockTypePublic,
		Bytes: publicKeyBytes,
	}

	var publicKeyPem bytes.Buffer
	if err = pem.Encode(&publicKeyPem, publicKeyBlock); err != nil {
		return Key{}, err
	}

	return Key{Public: publicKeyPem.Bytes(), Private: privateKeyPem.Bytes()}, nil
}
