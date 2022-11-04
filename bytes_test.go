// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"path/filepath"
	"testing"
)

// go test -v -cover -run=^TestBytes$
func TestBytes(t *testing.T) {
	str := "Hello World"

	bs := Bytes(str)
	if !bytes.Equal(bs.Bytes(), bs) {
		t.Errorf("bs.Bytes() %+v != []byte(str) %+v", bs.Bytes(), []byte(str))
	}

	if bs.String() != str {
		t.Errorf("bs.String() %s != str %s", bs.String(), str)
	}

	expect := hex.EncodeToString(bs)
	if bs.Hex() != expect {
		t.Errorf("bs.String() %s != expect %s", bs.String(), expect)
	}

	expect = base64.StdEncoding.EncodeToString(bs)
	if bs.Base64() != base64.StdEncoding.EncodeToString(bs) {
		t.Errorf("bs.String() %s != expect %s", bs.String(), expect)
	}
}

// go test -v -cover -run=^TestBytesClone$
func TestBytesClone(t *testing.T) {
	bs := Bytes("Hello World")
	newSlice := bs.Clone()

	if string(newSlice) != string(bs) {
		t.Errorf("newSlice %s != bs %s", string(newSlice), string(bs))
	}
}

// go test -v -cover -run=^TestBytesWriteTo$
func TestBytesWriteTo(t *testing.T) {
	bs := Bytes("你好，世界")

	var buff bytes.Buffer
	n, err := bs.WriteTo(&buff)
	if err != nil {
		t.Error(err)
	}

	if n != int64(len(bs)) {
		t.Errorf("n %d != int64(len(bs)) %d", n, int64(len(bs)))
	}

	if !bytes.Equal(bs, buff.Bytes()) {
		t.Errorf("bs %+v != buff.Bytes() %+v", bs, buff.Bytes())
	}
}

// go test -v -cover -run=^TestBytesWriteToFile$
func TestBytesWriteToFile(t *testing.T) {
	bs := Bytes("你好，世界")

	path := filepath.Join(t.TempDir(), t.Name()+".key")
	t.Log("path:", path)

	n, err := bs.WriteToFile(path)
	if err != nil {
		t.Error(err)
	}

	if n != int64(len(bs)) {
		t.Errorf("n %d != int64(len(bs)) %d", n, int64(len(bs)))
	}

	readBytes, err := ioutil.ReadFile(path)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(bs, readBytes) {
		t.Errorf("bs %+v != readBytes %+v", bs, readBytes)
	}
}

// go test -v -cover -run=^TestParseHex$
func TestParseHex(t *testing.T) {
	cases := map[string]string{
		"":                               "",
		"313233":                         "123",
		"e4bda0e5a5bdefbc8ce4b896e7958c": "你好，世界",
	}

	for encoded, expect := range cases {
		plain, err := ParseHex(encoded)
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("encoded %s: plainStr %s != expect %s", encoded, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestParseBase64$
func TestParseBase64(t *testing.T) {
	cases := map[string]string{
		"":                     "",
		"MTIz":                 "123",
		"5L2g5aW977yM5LiW55WM": "你好，世界",
	}

	for encoded, expect := range cases {
		plain, err := ParseBase64(encoded)
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("encoded %s: plainStr %s != expect %s", encoded, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestRandomBytes$
func TestRandomBytes(t *testing.T) {
	for i := 0; i < 16; i++ {
		n := i

		bs, err := RandomBytes(n)
		if err != nil {
			t.Error(err)
		}

		if len(bs) != n {
			t.Errorf("len(bs) %d != n %d", len(bs), n)
		}

		t.Log(bs)
	}
}
