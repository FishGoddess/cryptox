// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rsa"
	"io"
	"os"

	"github.com/FishGoddess/cryptox"
)

var (
	// KeyFileFlag is the flag of key file.
	KeyFileFlag = os.O_CREATE | os.O_APPEND | os.O_WRONLY

	// KeyFileMode is the mode of key file.
	KeyFileMode os.FileMode = 0644
)

// Key stores public key and private key of rsa.
type Key struct {
	Private      *rsa.PrivateKey
	Public       *rsa.PublicKey
	PrivateBytes cryptox.Bytes
	PublicBytes  cryptox.Bytes
}

// newFile creates a new file of path.
func (k *Key) newFile(path string) (*os.File, error) {
	return os.OpenFile(path, KeyFileFlag, KeyFileMode)
}

// WritePrivateTo writes private key to writer.
func (k *Key) WritePrivateTo(privateWriter io.Writer) (n int, err error) {
	return privateWriter.Write(k.PrivateBytes)
}

// WritePublicTo writes public key to writer.
func (k *Key) WritePublicTo(publicWriter io.Writer) (n int, err error) {
	return publicWriter.Write(k.PublicBytes)
}

// WriteTo writes private key and public key to writer.
func (k *Key) WriteTo(privateWriter io.Writer, publicWriter io.Writer) (n int, err error) {
	n, err = k.WritePrivateTo(privateWriter)
	if err != nil {
		return n, err
	}

	nn, err := k.WritePublicTo(publicWriter)
	if err != nil {
		return n + nn, err
	}

	return n + nn, nil
}

// WritePrivateToFile writes private key to file.
func (k *Key) WritePrivateToFile(privatePath string) (n int, err error) {
	privateFile, err := k.newFile(privatePath)
	if err != nil {
		return 0, err
	}

	defer privateFile.Close()
	return k.WritePrivateTo(privateFile)
}

// WritePublicToFile writes public key to file.
func (k *Key) WritePublicToFile(publicPath string) (n int, err error) {
	publicFile, err := k.newFile(publicPath)
	if err != nil {
		return 0, err
	}

	defer publicFile.Close()

	return k.WritePublicTo(publicFile)
}

// WriteToFile writes private key and public key to file.
func (k *Key) WriteToFile(privatePath string, publicPath string) (n int, err error) {
	n, err = k.WritePrivateToFile(privatePath)
	if err != nil {
		return n, err
	}

	nn, err := k.WritePublicToFile(publicPath)
	if err != nil {
		return n + nn, err
	}

	return n + nn, nil
}

type PrivateKey struct {
	key *rsa.PrivateKey
	bs  cryptox.Bytes
}

func newPrivateKey(key *rsa.PrivateKey, bs cryptox.Bytes) PrivateKey {
	return PrivateKey{key: key, bs: bs}
}

func (pk PrivateKey) Key() *rsa.PrivateKey {
	return pk.key
}

func (pk PrivateKey) Encoded() cryptox.Bytes {
	return pk.bs
}

func (pk PrivateKey) String() string {
	return pk.bs.String()
}

func (pk PrivateKey) EqualsTo(privateKey PrivateKey) bool {
	return pk.key.Equal(privateKey)
}

type PublicKey struct {
	key *rsa.PublicKey
	bs  cryptox.Bytes
}

func newPublicKey(key *rsa.PublicKey, bs cryptox.Bytes) PublicKey {
	return PublicKey{key: key, bs: bs}
}

func (pk PublicKey) Key() *rsa.PublicKey {
	return pk.key
}

func (pk PublicKey) Encoded() cryptox.Bytes {
	return pk.bs
}

func (pk PublicKey) String() string {
	return pk.bs.String()
}

func (pk PublicKey) EqualsTo(publicKey PublicKey) bool {
	return pk.key.Equal(publicKey.key)
}
