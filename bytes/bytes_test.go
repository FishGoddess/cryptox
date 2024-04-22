// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package bytes

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// go test -v -cover -count=1 -test.cpu=1 -run=^TestCopy$
func TestCopy(t *testing.T) {
	bs := []byte("Hello World")
	got := Copy(bs)

	if !bytes.Equal(got, bs) {
		t.Errorf("got %+v != bs %+v", string(got), string(bs))
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestWriteFile$
func TestWriteFile(t *testing.T) {
	bs := []byte("你好，世界")

	filename := filepath.Join(t.TempDir(), t.Name()+".txt")
	t.Log("filename:", filename)

	n, err := WriteFile(filename, bs)
	if err != nil {
		t.Fatal(err)
	}

	if n != len(bs) {
		t.Fatalf("n %d != len(bs) %d", n, len(bs))
	}

	readBytes, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bs, readBytes) {
		t.Errorf("bs %+v != readBytes %+v", bs, readBytes)
	}
}
