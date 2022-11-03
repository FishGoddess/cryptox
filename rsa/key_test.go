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

// go test -v -cover -run=^TestKeyWritePrivateTo$
func TestKeyWritePrivateTo(t *testing.T) {
	key := Key{
		PrivateBytes: []byte("private"),
	}

	var privateBuffer bytes.Buffer
	n, err := key.WritePrivateTo(&privateBuffer)
	if err != nil {
		t.Error(err)
	}

	if n != len(key.PrivateBytes) {
		t.Errorf("n %d != len(key.PrivateBytes) %d", n, len(key.PrivateBytes))
	}

	if !bytes.Equal(key.PrivateBytes, privateBuffer.Bytes()) {
		t.Errorf("key.PrivateBytes %+v != privateBuffer.Bytes() %+v", key.PrivateBytes, privateBuffer.Bytes())
	}
}

// go test -v -cover -run=^TestKeyWritePublicTo$
func TestKeyWritePublicTo(t *testing.T) {
	key := Key{
		PublicBytes: []byte("public"),
	}

	var publicBuffer bytes.Buffer
	n, err := key.WritePublicTo(&publicBuffer)
	if err != nil {
		t.Error(err)
	}

	if n != len(key.PublicBytes) {
		t.Errorf("n %d != len(key.PublicBytes) %d", n, len(key.PublicBytes))
	}

	if !bytes.Equal(key.PublicBytes, publicBuffer.Bytes()) {
		t.Errorf("key.PublicBytes %+v != publicBuffer.Bytes() %+v", key.PublicBytes, publicBuffer.Bytes())
	}
}

// go test -v -cover -run=^TestKeyWriteTo$
func TestKeyWriteTo(t *testing.T) {
	key := Key{
		PrivateBytes: []byte("private"),
		PublicBytes:  []byte("public"),
	}

	var privateBuffer, publicBuffer bytes.Buffer
	n, err := key.WriteTo(&privateBuffer, &publicBuffer)
	if err != nil {
		t.Error(err)
	}

	if n != len(key.PrivateBytes)+len(key.PublicBytes) {
		t.Errorf("n %d != len(key.PrivateBytes) %d + len(key.PublicBytes) %d", n, len(key.PrivateBytes), len(key.PublicBytes))
	}

	if !bytes.Equal(key.PrivateBytes, privateBuffer.Bytes()) {
		t.Errorf("key.PrivateBytes %+v != privateBuffer.Bytes() %+v", key.PrivateBytes, privateBuffer.Bytes())
	}

	if !bytes.Equal(key.PublicBytes, publicBuffer.Bytes()) {
		t.Errorf("key.PublicBytes %+v != publicBuffer.Bytes() %+v", key.PublicBytes, publicBuffer.Bytes())
	}
}

// go test -v -cover -run=^TestKeyWritePrivateToFile$
func TestKeyWritePrivateToFile(t *testing.T) {
	key := Key{
		PrivateBytes: []byte("private"),
	}

	privatePath := filepath.Join(t.TempDir(), t.Name()+".key")
	t.Log("private path:", privatePath)

	n, err := key.WritePrivateToFile(privatePath)
	if err != nil {
		t.Error(err)
	}

	if n != len(key.PrivateBytes) {
		t.Errorf("n %d != len(key.PrivateBytes) %d", n, len(key.PrivateBytes))
	}

	privateBytes, err := ioutil.ReadFile(privatePath)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(key.PrivateBytes, privateBytes) {
		t.Errorf("key.PrivateBytes %+v != privateBytes %+v", key.PrivateBytes, privateBytes)
	}
}

// go test -v -cover -run=^TestKeyWritePublicToFile$
func TestKeyWritePublicToFile(t *testing.T) {
	key := Key{
		PublicBytes: []byte("public"),
	}

	publicPath := filepath.Join(t.TempDir(), t.Name()+".pub")
	t.Log("public path:", publicPath)

	n, err := key.WritePublicToFile(publicPath)
	if err != nil {
		t.Error(err)
	}

	if n != len(key.PublicBytes) {
		t.Errorf("n %d != len(key.PublicBytes) %d", n, len(key.PublicBytes))
	}

	publicBytes, err := ioutil.ReadFile(publicPath)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(key.PublicBytes, publicBytes) {
		t.Errorf("key.PublicBytes %+v != publicBytes %+v", key.PublicBytes, publicBytes)
	}
}

// go test -v -cover -run=^TestKeyWriteToFile$
func TestKeyWriteToFile(t *testing.T) {
	key := Key{
		PrivateBytes: []byte("private"),
		PublicBytes:  []byte("public"),
	}

	privatePath := filepath.Join(t.TempDir(), t.Name()+".key")
	publicPath := filepath.Join(t.TempDir(), t.Name()+".pub")
	t.Log("private path:", privatePath)
	t.Log("public path:", publicPath)

	n, err := key.WriteToFile(privatePath, publicPath)
	if err != nil {
		t.Error(err)
	}

	if n != len(key.PrivateBytes)+len(key.PublicBytes) {
		t.Errorf("n %d != len(key.PrivateBytes) %d + len(key.PublicBytes) %d", n, len(key.PrivateBytes), len(key.PublicBytes))
	}

	privateBytes, err := ioutil.ReadFile(privatePath)
	if err != nil {
		t.Error(err)
	}

	publicBytes, err := ioutil.ReadFile(publicPath)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(key.PrivateBytes, privateBytes) {
		t.Errorf("key.PrivateBytes %+v != privateBytes %+v", key.PrivateBytes, privateBytes)
	}

	if !bytes.Equal(key.PublicBytes, publicBytes) {
		t.Errorf("key.PublicBytes %+v != publicBytes %+v", key.PublicBytes, publicBytes)
	}
}
