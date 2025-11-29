// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hmac

import (
	"fmt"
	"slices"
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
)

type testHashFunc = func(bs []byte, key []byte, encoding encoding.Encoding) []byte

type testCase struct {
	Data           []byte
	HashData       []byte
	HashDataHex    []byte
	HashDataBase64 []byte
}

func testHash(name string, hash testHashFunc, testCases []testCase) error {
	key := []byte("key")
	for _, testCase := range testCases {
		// None
		got := hash(testCase.Data, key, encoding.None)
		if !slices.Equal(got, testCase.HashData) {
			return fmt.Errorf("%s data %q: got %+v != expect %+v", name, testCase.Data, got, testCase.HashData)
		}

		// Hex
		got = hash(testCase.Data, key, encoding.Hex)
		if !slices.Equal(got, testCase.HashDataHex) {
			return fmt.Errorf("%s data %q: got hex %s != expect hex %s", name, testCase.Data, got, testCase.HashDataHex)
		}

		// Base64
		got = hash(testCase.Data, key, encoding.Base64)
		if !slices.Equal(got, testCase.HashDataBase64) {
			return fmt.Errorf("%s data %q: got base64 %s != expect base64 %s", name, testCase.Data, got, testCase.HashDataBase64)
		}
	}

	return nil
}

// go test -v -cover -run=^TestMD5$
func TestMD5(t *testing.T) {
	testCases := []testCase{
		{
			Data:           []byte(""),
			HashData:       []byte{99, 83, 4, 104, 160, 78, 56, 100, 89, 133, 93, 160, 6, 59, 101, 150},
			HashDataHex:    []byte("63530468a04e386459855da0063b6596"),
			HashDataBase64: []byte("Y1MEaKBOOGRZhV2gBjtllg=="),
		},
		{
			Data:           []byte("123"),
			HashData:       []byte{82, 133, 28, 176, 82, 88, 200, 217, 141, 161, 103, 45, 149, 114, 158, 83},
			HashDataHex:    []byte("52851cb05258c8d98da1672d95729e53"),
			HashDataBase64: []byte("UoUcsFJYyNmNoWctlXKeUw=="),
		},
		{
			Data:           []byte("你好，世界"),
			HashData:       []byte{231, 109, 143, 132, 16, 53, 51, 220, 93, 34, 166, 224, 12, 239, 116, 243},
			HashDataHex:    []byte("e76d8f84103533dc5d22a6e00cef74f3"),
			HashDataBase64: []byte("522PhBA1M9xdIqbgDO908w=="),
		},
	}

	testHash(t.Name(), MD5, testCases)
}

// go test -v -cover -run=^TestSHA1$
func TestSHA1(t *testing.T) {
	testCases := []testCase{
		{
			Data:           []byte(""),
			HashData:       []byte{244, 43, 176, 238, 176, 24, 235, 189, 69, 151, 174, 114, 19, 113, 30, 198, 7, 96, 132, 63},
			HashDataHex:    []byte("f42bb0eeb018ebbd4597ae7213711ec60760843f"),
			HashDataBase64: []byte("9Cuw7rAY671Fl65yE3EexgdghD8="),
		},
		{
			Data:           []byte("123"),
			HashData:       []byte{212, 165, 182, 114, 29, 117, 165, 172, 21, 236, 105, 136, 24, 199, 127, 225, 246, 228, 1, 135},
			HashDataHex:    []byte("d4a5b6721d75a5ac15ec698818c77fe1f6e40187"),
			HashDataBase64: []byte("1KW2ch11pawV7GmIGMd/4fbkAYc="),
		},
		{
			Data:           []byte("你好，世界"),
			HashData:       []byte{3, 171, 78, 157, 35, 50, 230, 100, 251, 171, 132, 10, 152, 8, 32, 181, 236, 42, 95, 173},
			HashDataHex:    []byte("03ab4e9d2332e664fbab840a980820b5ec2a5fad"),
			HashDataBase64: []byte("A6tOnSMy5mT7q4QKmAggtewqX60="),
		},
	}

	testHash(t.Name(), SHA1, testCases)
}

// go test -v -cover -run=^TestSHA224$
func TestSHA224(t *testing.T) {
	testCases := []testCase{
		{
			Data:           []byte(""),
			HashData:       []byte{90, 166, 119, 193, 60, 225, 18, 142, 235, 58, 92, 1, 206, 247, 241, 101, 87, 205, 11, 118, 209, 143, 213, 87, 214, 172, 57, 98},
			HashDataHex:    []byte("5aa677c13ce1128eeb3a5c01cef7f16557cd0b76d18fd557d6ac3962"),
			HashDataBase64: []byte("WqZ3wTzhEo7rOlwBzvfxZVfNC3bRj9VX1qw5Yg=="),
		},
		{
			Data:           []byte("123"),
			HashData:       []byte{0, 54, 98, 61, 40, 118, 56, 63, 27, 244, 38, 215, 202, 143, 70, 136, 79, 13, 129, 31, 102, 65, 24, 178, 249, 60, 119, 75},
			HashDataHex:    []byte("0036623d2876383f1bf426d7ca8f46884f0d811f664118b2f93c774b"),
			HashDataBase64: []byte("ADZiPSh2OD8b9CbXyo9GiE8NgR9mQRiy+Tx3Sw=="),
		},
		{
			Data:           []byte("你好，世界"),
			HashData:       []byte{191, 33, 209, 244, 26, 17, 113, 26, 67, 85, 158, 252, 102, 193, 105, 243, 60, 155, 101, 129, 50, 143, 205, 176, 25, 122, 188, 131},
			HashDataHex:    []byte("bf21d1f41a11711a43559efc66c169f33c9b6581328fcdb0197abc83"),
			HashDataBase64: []byte("vyHR9BoRcRpDVZ78ZsFp8zybZYEyj82wGXq8gw=="),
		},
	}

	testHash(t.Name(), SHA224, testCases)
}

// go test -v -cover -run=^TestSHA256$
func TestSHA256(t *testing.T) {
	testCases := []testCase{
		{
			Data:           []byte(""),
			HashData:       []byte{93, 93, 19, 149, 99, 201, 91, 89, 103, 185, 189, 154, 140, 155, 35, 58, 157, 237, 180, 80, 114, 121, 76, 210, 50, 220, 27, 116, 131, 38, 7, 208},
			HashDataHex:    []byte("5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0"),
			HashDataBase64: []byte("XV0TlWPJW1lnub2ajJsjOp3ttFByeUzSMtwbdIMmB9A="),
		},
		{
			Data:           []byte("123"),
			HashData:       []byte{167, 247, 115, 155, 29, 197, 180, 233, 34, 177, 34, 108, 159, 203, 220, 131, 73, 141, 238, 55, 83, 130, 202, 238, 8, 253, 82, 161, 62, 183, 207, 226},
			HashDataHex:    []byte("a7f7739b1dc5b4e922b1226c9fcbdc83498dee375382caee08fd52a13eb7cfe2"),
			HashDataBase64: []byte("p/dzmx3FtOkisSJsn8vcg0mN7jdTgsruCP1SoT63z+I="),
		},
		{
			Data:           []byte("你好，世界"),
			HashData:       []byte{236, 235, 194, 105, 101, 153, 153, 213, 10, 111, 116, 116, 63, 88, 20, 207, 8, 0, 12, 127, 125, 161, 191, 78, 253, 70, 237, 101, 23, 120, 237, 148},
			HashDataHex:    []byte("ecebc269659999d50a6f74743f5814cf08000c7f7da1bf4efd46ed651778ed94"),
			HashDataBase64: []byte("7OvCaWWZmdUKb3R0P1gUzwgADH99ob9O/UbtZRd47ZQ="),
		},
	}

	testHash(t.Name(), SHA256, testCases)
}

// go test -v -cover -run=^TestSHA384$
func TestSHA384(t *testing.T) {
	testCases := []testCase{
		{
			Data:           []byte(""),
			HashData:       []byte{153, 244, 75, 180, 231, 60, 157, 14, 242, 101, 51, 89, 108, 141, 138, 50, 165, 248, 193, 10, 155, 153, 125, 48, 216, 154, 126, 53, 186, 28, 207, 32, 11, 152, 95, 114, 67, 18, 2, 184, 145, 254, 53, 13, 164, 16, 228, 63},
			HashDataHex:    []byte("99f44bb4e73c9d0ef26533596c8d8a32a5f8c10a9b997d30d89a7e35ba1ccf200b985f72431202b891fe350da410e43f"),
			HashDataBase64: []byte("mfRLtOc8nQ7yZTNZbI2KMqX4wQqbmX0w2Jp+NboczyALmF9yQxICuJH+NQ2kEOQ/"),
		},
		{
			Data:           []byte("123"),
			HashData:       []byte{169, 76, 153, 102, 189, 83, 13, 101, 181, 176, 159, 210, 38, 71, 153, 38, 190, 240, 55, 112, 94, 32, 144, 160, 178, 74, 177, 25, 34, 216, 33, 167, 7, 108, 10, 139, 193, 32, 169, 180, 158, 65, 205, 56, 66, 142, 199, 236},
			HashDataHex:    []byte("a94c9966bd530d65b5b09fd226479926bef037705e2090a0b24ab11922d821a7076c0a8bc120a9b49e41cd38428ec7ec"),
			HashDataBase64: []byte("qUyZZr1TDWW1sJ/SJkeZJr7wN3BeIJCgskqxGSLYIacHbAqLwSCptJ5BzThCjsfs"),
		},
		{
			Data:           []byte("你好，世界"),
			HashData:       []byte{73, 203, 21, 108, 84, 87, 47, 63, 162, 127, 232, 130, 244, 240, 142, 236, 6, 52, 116, 53, 243, 246, 65, 224, 66, 183, 24, 202, 184, 232, 209, 236, 202, 118, 180, 30, 101, 127, 244, 101, 145, 255, 108, 94, 253, 137, 193, 163},
			HashDataHex:    []byte("49cb156c54572f3fa27fe882f4f08eec06347435f3f641e042b718cab8e8d1ecca76b41e657ff46591ff6c5efd89c1a3"),
			HashDataBase64: []byte("ScsVbFRXLz+if+iC9PCO7AY0dDXz9kHgQrcYyrjo0ezKdrQeZX/0ZZH/bF79icGj"),
		},
	}

	testHash(t.Name(), SHA384, testCases)
}

// go test -v -cover -run=^TestSHA512$
func TestSHA512(t *testing.T) {
	testCases := []testCase{
		{
			Data:           []byte(""),
			HashData:       []byte{132, 250, 90, 160, 39, 155, 188, 71, 50, 103, 208, 90, 83, 234, 3, 49, 10, 152, 124, 236, 196, 193, 83, 95, 242, 155, 109, 118, 184, 241, 68, 74, 114, 141, 243, 170, 219, 137, 212, 169, 166, 112, 158, 25, 152, 243, 115, 86, 110, 143, 130, 74, 140, 169, 59, 24, 33, 240, 182, 155, 194, 162, 246, 94},
			HashDataHex:    []byte("84fa5aa0279bbc473267d05a53ea03310a987cecc4c1535ff29b6d76b8f1444a728df3aadb89d4a9a6709e1998f373566e8f824a8ca93b1821f0b69bc2a2f65e"),
			HashDataBase64: []byte("hPpaoCebvEcyZ9BaU+oDMQqYfOzEwVNf8pttdrjxREpyjfOq24nUqaZwnhmY83NWbo+CSoypOxgh8LabwqL2Xg=="),
		},
		{
			Data:           []byte("123"),
			HashData:       []byte{46, 168, 35, 198, 69, 177, 186, 248, 69, 239, 118, 9, 106, 109, 127, 169, 229, 104, 48, 75, 169, 247, 145, 11, 213, 47, 1, 192, 62, 236, 57, 205, 254, 236, 84, 229, 11, 134, 182, 46, 245, 191, 185, 230, 206, 92, 11, 231, 71, 236, 19, 179, 161, 153, 249, 210, 53, 233, 154, 54, 222, 54, 154, 132},
			HashDataHex:    []byte("2ea823c645b1baf845ef76096a6d7fa9e568304ba9f7910bd52f01c03eec39cdfeec54e50b86b62ef5bfb9e6ce5c0be747ec13b3a199f9d235e99a36de369a84"),
			HashDataBase64: []byte("LqgjxkWxuvhF73YJam1/qeVoMEup95EL1S8BwD7sOc3+7FTlC4a2LvW/uebOXAvnR+wTs6GZ+dI16Zo23jaahA=="),
		},
		{
			Data:           []byte("你好，世界"),
			HashData:       []byte{249, 42, 172, 143, 231, 38, 246, 29, 114, 71, 191, 145, 140, 15, 17, 139, 254, 244, 236, 209, 118, 92, 54, 60, 229, 55, 56, 19, 15, 105, 7, 85, 85, 35, 99, 227, 135, 134, 154, 74, 92, 247, 240, 254, 88, 122, 46, 106, 109, 121, 164, 241, 19, 220, 114, 41, 169, 132, 94, 91, 148, 201, 104, 159},
			HashDataHex:    []byte("f92aac8fe726f61d7247bf918c0f118bfef4ecd1765c363ce53738130f690755552363e387869a4a5cf7f0fe587a2e6a6d79a4f113dc7229a9845e5b94c9689f"),
			HashDataBase64: []byte("+Sqsj+cm9h1yR7+RjA8Ri/707NF2XDY85Tc4Ew9pB1VVI2Pjh4aaSlz38P5Yei5qbXmk8RPccimphF5blMlonw=="),
		},
	}

	testHash(t.Name(), SHA512, testCases)
}
