// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hmac

import (
	"slices"
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
)

type testHashFunc = func(key []byte, bs []byte, encoding encoding.Encoding) []byte

type testCase struct {
	Data     []byte
	Expect   []byte
	Encoding encoding.Encoding
}

func testHash(t *testing.T, hash testHashFunc, testCases []testCase) {
	key := "key"
	for _, testCase := range testCases {
		got := hash([]byte(key), []byte(testCase.Data), testCase.Encoding)
		if !slices.Equal(got, testCase.Expect) {
			t.Fatalf("data %s: got %s != expect %s", testCase.Data, got, testCase.Expect)
		}
	}
}

// go test -v -cover -run=^TestMD5$
func TestMD5(t *testing.T) {
	testCases := []testCase{
		{Data: []byte(""), Expect: []byte("63530468a04e386459855da0063b6596"), Encoding: encoding.Hex},
		{Data: []byte("123"), Expect: []byte("52851cb05258c8d98da1672d95729e53"), Encoding: encoding.Hex},
		{Data: []byte("你好，世界"), Expect: []byte("e76d8f84103533dc5d22a6e00cef74f3"), Encoding: encoding.Hex},
	}

	testHash(t, MD5, testCases)
}

// go test -v -cover -run=^TestSHA1$
func TestSHA1(t *testing.T) {
	testCases := []testCase{
		{Data: []byte(""), Expect: []byte("f42bb0eeb018ebbd4597ae7213711ec60760843f"), Encoding: encoding.Hex},
		{Data: []byte("123"), Expect: []byte("d4a5b6721d75a5ac15ec698818c77fe1f6e40187"), Encoding: encoding.Hex},
		{Data: []byte("你好，世界"), Expect: []byte("03ab4e9d2332e664fbab840a980820b5ec2a5fad"), Encoding: encoding.Hex},
	}

	testHash(t, SHA1, testCases)
}

// go test -v -cover -run=^TestSHA224$
func TestSHA224(t *testing.T) {
	testCases := []testCase{
		{Data: []byte(""), Expect: []byte("5aa677c13ce1128eeb3a5c01cef7f16557cd0b76d18fd557d6ac3962"), Encoding: encoding.Hex},
		{Data: []byte("123"), Expect: []byte("0036623d2876383f1bf426d7ca8f46884f0d811f664118b2f93c774b"), Encoding: encoding.Hex},
		{Data: []byte("你好，世界"), Expect: []byte("bf21d1f41a11711a43559efc66c169f33c9b6581328fcdb0197abc83"), Encoding: encoding.Hex},
	}

	testHash(t, SHA224, testCases)
}

// go test -v -cover -run=^TestSHA256$
func TestSHA256(t *testing.T) {
	testCases := []testCase{
		{Data: []byte(""), Expect: []byte("5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0"), Encoding: encoding.Hex},
		{Data: []byte("123"), Expect: []byte("a7f7739b1dc5b4e922b1226c9fcbdc83498dee375382caee08fd52a13eb7cfe2"), Encoding: encoding.Hex},
		{Data: []byte("你好，世界"), Expect: []byte("ecebc269659999d50a6f74743f5814cf08000c7f7da1bf4efd46ed651778ed94"), Encoding: encoding.Hex},
	}

	testHash(t, SHA256, testCases)
}

// go test -v -cover -run=^TestSHA384$
func TestSHA384(t *testing.T) {
	testCases := []testCase{
		{Data: []byte(""), Expect: []byte("99f44bb4e73c9d0ef26533596c8d8a32a5f8c10a9b997d30d89a7e35ba1ccf200b985f72431202b891fe350da410e43f"), Encoding: encoding.Hex},
		{Data: []byte("123"), Expect: []byte("a94c9966bd530d65b5b09fd226479926bef037705e2090a0b24ab11922d821a7076c0a8bc120a9b49e41cd38428ec7ec"), Encoding: encoding.Hex},
		{Data: []byte("你好，世界"), Expect: []byte("49cb156c54572f3fa27fe882f4f08eec06347435f3f641e042b718cab8e8d1ecca76b41e657ff46591ff6c5efd89c1a3"), Encoding: encoding.Hex},
	}

	testHash(t, SHA384, testCases)
}

// go test -v -cover -run=^TestSHA512$
func TestSHA512(t *testing.T) {
	testCases := []testCase{
		{Data: []byte(""), Expect: []byte("84fa5aa0279bbc473267d05a53ea03310a987cecc4c1535ff29b6d76b8f1444a728df3aadb89d4a9a6709e1998f373566e8f824a8ca93b1821f0b69bc2a2f65e"), Encoding: encoding.Hex},
		{Data: []byte("123"), Expect: []byte("2ea823c645b1baf845ef76096a6d7fa9e568304ba9f7910bd52f01c03eec39cdfeec54e50b86b62ef5bfb9e6ce5c0be747ec13b3a199f9d235e99a36de369a84"), Encoding: encoding.Hex},
		{Data: []byte("你好，世界"), Expect: []byte("f92aac8fe726f61d7247bf918c0f118bfef4ecd1765c363ce53738130f690755552363e387869a4a5cf7f0fe587a2e6a6d79a4f113dc7229a9845e5b94c9689f"), Encoding: encoding.Hex},
	}

	testHash(t, SHA512, testCases)
}
