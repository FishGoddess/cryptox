// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// go test -v -cover -count=1 -test.cpu=1 -run=^TestBytes$
func TestBytes(t *testing.T) {
	str := "Hello World"

	bs := Bytes(str)
	if !bytes.Equal(bs, []byte(str)) {
		t.Fatalf("bs %+v != []byte(str) %+v", bs, []byte(str))
	}

	expect := hex.EncodeToString(bs)
	if bs.Hex() != expect {
		t.Fatalf("bs.Hex() %s != expect %s", bs.Hex(), expect)
	}

	expect = base64.StdEncoding.EncodeToString(bs)
	if bs.Base64() != expect {
		t.Fatalf("bs.Base64() %s != expect %s", bs.Base64(), expect)
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestBytesClone$
func TestBytesClone(t *testing.T) {
	bs := Bytes("Hello World")
	newSlice := bs.Clone()

	if !bytes.Equal(newSlice, bs) {
		t.Fatalf("newSlice %+v != bs %+v", newSlice, bs)
	}

	bs[0] = '\n'
	if bytes.Equal(newSlice, bs) {
		t.Fatalf("newSlice %+v == bs %+v", newSlice, bs)
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestBytesWriteTo$
func TestBytesWriteTo(t *testing.T) {
	bs := Bytes("你好，世界")

	var buff bytes.Buffer
	n, err := bs.WriteTo(&buff)
	if err != nil {
		t.Fatal(err)
	}

	if n != int64(len(bs)) {
		t.Fatalf("n %d != int64(len(bs)) %d", n, int64(len(bs)))
	}

	if !bytes.Equal(bs, buff.Bytes()) {
		t.Fatalf("bs %+v != buff.Bytes() %+v", bs, buff.Bytes())
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestBytesWriteToFile$
func TestBytesWriteToFile(t *testing.T) {
	bs := Bytes("你好，世界")

	path := filepath.Join(t.TempDir(), t.Name()+".key")
	t.Log("path:", path)

	n, err := bs.WriteToFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if n != int64(len(bs)) {
		t.Fatalf("n %d != int64(len(bs)) %d", n, int64(len(bs)))
	}

	readBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bs, readBytes) {
		t.Fatalf("bs %+v != readBytes %+v", bs, readBytes)
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestParseHex$
func TestParseHex(t *testing.T) {
	cases := map[string]string{
		"":                               "",
		"313233":                         "123",
		"e4bda0e5a5bdefbc8ce4b896e7958c": "你好，世界",
	}

	for encoded, expect := range cases {
		decoded, err := ParseHex(encoded)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(decoded, []byte(expect)) {
			t.Fatalf("encoded %s: decoded %+v != expect %+v", encoded, decoded, []byte(expect))
		}
	}
}

// go test -v -cover -count=1 -test.cpu=1 -run=^TestFromBase64$
func TestFromBase64(t *testing.T) {
	cases := map[string]string{
		"":                     "",
		"MTIz":                 "123",
		"5L2g5aW977yM5LiW55WM": "你好，世界",
	}

	for encoded, expect := range cases {
		decoded, err := ParseBase64(encoded)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(decoded, []byte(expect)) {
			t.Fatalf("encoded %s: decoded %+v != expect %+v", encoded, decoded, []byte(expect))
		}
	}
}
