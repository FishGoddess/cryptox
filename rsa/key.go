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
	"errors"
	"io"
	"os"

	"github.com/FishGoddess/cryptox"
)

const (
	blockTypePrivate = "RSA Private Key"
	blockTypePublic  = "RSA Public Key"
)

var (
	// KeyFileFlag is the flag of key file.
	KeyFileFlag = os.O_CREATE | os.O_APPEND | os.O_WRONLY

	// KeyFileMode is the mode of key file.
	KeyFileMode os.FileMode = 0644
)

var (
	// MarshalPrivateKey marshals private key to bytes.
	MarshalPrivateKey = func(key *rsa.PrivateKey) ([]byte, error) {
		return x509.MarshalPKCS1PrivateKey(key), nil
	}

	// MarshalPublicKey marshals public key to bytes.
	MarshalPublicKey = func(key *rsa.PublicKey) ([]byte, error) {
		return x509.MarshalPKIXPublicKey(key)
	}

	// ParsePrivateKey parses private key from data.
	ParsePrivateKey = func(data cryptox.Bytes) (*rsa.PrivateKey, error) {
		return x509.ParsePKCS1PrivateKey(data)
	}
)

// Key stores public key and private key of rsa.
type Key struct {
	Private cryptox.Bytes
	Public  cryptox.Bytes
}

// newFile creates a new file of path.
func (k Key) newFile(path string) (*os.File, error) {
	return os.OpenFile(path, KeyFileFlag, KeyFileMode)
}

// WriteTo writes private key and public key to writer.
func (k Key) WriteTo(privateWriter io.Writer, publicWriter io.Writer) (n int, err error) {
	n, err = privateWriter.Write(k.Private)
	if err != nil {
		return n, err
	}

	nn, err := publicWriter.Write(k.Public)
	if err != nil {
		return n + nn, err
	}

	return n + nn, nil
}

// WriteToFile writes private key and public key to file.
func (k Key) WriteToFile(privatePath string, publicPath string) (n int, err error) {
	privateFile, err := k.newFile(privatePath)
	if err != nil {
		return 0, err
	}

	defer privateFile.Close()

	publicFile, err := k.newFile(publicPath)
	if err != nil {
		return 0, err
	}

	defer publicFile.Close()

	return k.WriteTo(privateFile, publicFile)
}

// GenerateKey generates a key set of bits.
func GenerateKey(bits int) (Key, error) {
	privateKey, privateKeyBytes, err := GeneratePrivateKey(bits)
	if err != nil {
		return Key{}, err
	}

	_, publicKeyBytes, err := GeneratePublicKey(privateKey)
	if err != nil {
		return Key{}, err
	}

	return Key{Public: publicKeyBytes, Private: privateKeyBytes}, nil
}

// GeneratePrivateKey generates a private key of bits.
// It returns an original key struct (*rsa.PrivateKey) and a completing key bytes (cryptox.Bytes).
func GeneratePrivateKey(bits int) (*rsa.PrivateKey, cryptox.Bytes, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	privateKeyBytes, err := MarshalPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	privateKeyBlock := &pem.Block{
		Type:  blockTypePrivate,
		Bytes: privateKeyBytes,
	}

	var privateKeyPem bytes.Buffer
	if err = pem.Encode(&privateKeyPem, privateKeyBlock); err != nil {
		return nil, nil, err
	}

	return privateKey, privateKeyPem.Bytes(), nil
}

// GeneratePublicKey generates a public key from private key.
// It returns an original key struct (*rsa.PublicKey) and a completing key bytes (cryptox.Bytes).
func GeneratePublicKey(privateKey *rsa.PrivateKey) (*rsa.PublicKey, cryptox.Bytes, error) {
	publicKey := &privateKey.PublicKey

	publicKeyBytes, err := MarshalPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}

	publicKeyBlock := &pem.Block{
		Type:  blockTypePublic,
		Bytes: publicKeyBytes,
	}

	var publicKeyPem bytes.Buffer
	if err = pem.Encode(&publicKeyPem, publicKeyBlock); err != nil {
		return nil, nil, err
	}

	return publicKey, publicKeyPem.Bytes(), nil
}

// GeneratePublicKeyFromPem generates a public key from private key pem.
// It returns an original key struct (*rsa.PublicKey) and a completing key bytes (cryptox.Bytes).
func GeneratePublicKeyFromPem(privateKeyPem cryptox.Bytes) (*rsa.PublicKey, cryptox.Bytes, error) {
	block, _ := pem.Decode(privateKeyPem)
	if block == nil {
		return nil, nil, errors.New("cryptox.rsa: decode private key from pem failed")
	}

	privateKey, err := ParsePrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return GeneratePublicKey(privateKey)
}
