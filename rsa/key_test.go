// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"bytes"
	"io/ioutil"
	"path/filepath"
	"testing"
)

// go test -v -cover -run=^TestGenerateKey$
func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey(2048)
	if err != nil {
		t.Error(err)
	}

	t.Log("Public Key:", key.Public)
	t.Log("Private Key:", key.Private)
}

// go test -v -cover -run=^TestKeyWriteTo$
func TestKeyWriteTo(t *testing.T) {
	key, err := GenerateKey(2048)
	if err != nil {
		t.Error(err)
	}

	var publicBuffer, privateBuffer bytes.Buffer
	n, err := key.WriteTo(&publicBuffer, &privateBuffer)
	if err != nil {
		t.Error(err)
	}

	if n != len(key.Public)+len(key.Private) {
		t.Errorf("n %d != len(key.Public) %d + len(key.Private) %d", n, len(key.Public), len(key.Private))
	}

	if !bytes.Equal(key.Public, publicBuffer.Bytes()) {
		t.Errorf("key.Public %+v != publicBuffer.Bytes() %+v", key.Public, publicBuffer.Bytes())
	}

	if !bytes.Equal(key.Private, privateBuffer.Bytes()) {
		t.Errorf("key.Private %+v != privateBuffer.Bytes() %+v", key.Private, privateBuffer.Bytes())
	}
}

// go test -v -cover -run=^TestKeyWriteToFile$
func TestKeyWriteToFile(t *testing.T) {
	key, err := GenerateKey(2048)
	if err != nil {
		t.Error(err)
	}

	publicPath := filepath.Join(t.TempDir(), "public.pem")
	privatePath := filepath.Join(t.TempDir(), "private.pem")
	t.Log("public path:", publicPath)
	t.Log("private path:", privatePath)

	n, err := key.WriteToFile(publicPath, privatePath)
	if err != nil {
		t.Error(err)
	}

	if n != len(key.Public)+len(key.Private) {
		t.Errorf("n %d != len(key.Public) %d + len(key.Private) %d", n, len(key.Public), len(key.Private))
	}

	publicBytes, err := ioutil.ReadFile(publicPath)
	if err != nil {
		t.Error(err)
	}

	privateBytes, err := ioutil.ReadFile(privatePath)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(key.Public, publicBytes) {
		t.Errorf("key.Public %+v != publicBytes %+v", key.Public, publicBytes)
	}

	if !bytes.Equal(key.Private, privateBytes) {
		t.Errorf("key.Private %+v != privateBytes %+v", key.Private, privateBytes)
	}
}
