// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"fmt"
	"slices"
	"testing"
)

type testHashFunc = func(bs []byte, opts ...Option) []byte

type testCase struct {
	Data           []byte
	HashData       []byte
	HashDataHex    []byte
	HashDataBase64 []byte
}

func testHash(name string, hash testHashFunc, testCases []testCase) error {
	for _, testCase := range testCases {
		// None
		got := hash(testCase.Data)
		if !slices.Equal(got, testCase.HashData) {
			return fmt.Errorf("%s data %q: got %+v != expect %+v", name, testCase.Data, got, testCase.HashData)
		}

		// Hex
		got = hash(testCase.Data, WithHex())
		if !slices.Equal(got, testCase.HashDataHex) {
			return fmt.Errorf("%s data %q: got hex %s != expect hex %s", name, testCase.Data, got, testCase.HashDataHex)
		}

		// Base64
		got = hash(testCase.Data, WithBase64())
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
			HashData:       []byte{212, 29, 140, 217, 143, 0, 178, 4, 233, 128, 9, 152, 236, 248, 66, 126},
			HashDataHex:    []byte("d41d8cd98f00b204e9800998ecf8427e"),
			HashDataBase64: []byte("1B2M2Y8AsgTpgAmY7PhCfg=="),
		},
		{
			Data:           []byte("123"),
			HashData:       []byte{32, 44, 185, 98, 172, 89, 7, 91, 150, 75, 7, 21, 45, 35, 75, 112},
			HashDataHex:    []byte("202cb962ac59075b964b07152d234b70"),
			HashDataBase64: []byte("ICy5YqxZB1uWSwcVLSNLcA=="),
		},
		{
			Data:           []byte("你好，世界"),
			HashData:       []byte{219, 239, 211, 173, 160, 24, 97, 91, 53, 88, 138, 1, 226, 22, 174, 110},
			HashDataHex:    []byte("dbefd3ada018615b35588a01e216ae6e"),
			HashDataBase64: []byte("2+/TraAYYVs1WIoB4haubg=="),
		},
	}

	if err := testHash(t.Name(), MD5, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestSHA1$
func TestSHA1(t *testing.T) {
	testCases := []testCase{
		{
			Data:           []byte(""),
			HashData:       []byte{218, 57, 163, 238, 94, 107, 75, 13, 50, 85, 191, 239, 149, 96, 24, 144, 175, 216, 7, 9},
			HashDataHex:    []byte("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
			HashDataBase64: []byte("2jmj7l5rSw0yVb/vlWAYkK/YBwk="),
		},
		{
			Data:           []byte("123"),
			HashData:       []byte{64, 189, 0, 21, 99, 8, 95, 195, 81, 101, 50, 158, 161, 255, 92, 94, 203, 219, 190, 239},
			HashDataHex:    []byte("40bd001563085fc35165329ea1ff5c5ecbdbbeef"),
			HashDataBase64: []byte("QL0AFWMIX8NRZTKeof9cXsvbvu8="),
		},
		{
			Data:           []byte("你好，世界"),
			HashData:       []byte{59, 236, 176, 59, 1, 94, 212, 128, 80, 97, 28, 141, 122, 254, 75, 136, 247, 13, 90, 32},
			HashDataHex:    []byte("3becb03b015ed48050611c8d7afe4b88f70d5a20"),
			HashDataBase64: []byte("O+ywOwFe1IBQYRyNev5LiPcNWiA="),
		},
	}

	if err := testHash(t.Name(), SHA1, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestSHA224$
func TestSHA224(t *testing.T) {
	testCases := []testCase{
		{
			Data:           []byte(""),
			HashData:       []byte{209, 74, 2, 140, 42, 58, 43, 201, 71, 97, 2, 187, 40, 130, 52, 196, 21, 162, 176, 31, 130, 142, 166, 42, 197, 179, 228, 47},
			HashDataHex:    []byte("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
			HashDataBase64: []byte("0UoCjCo6K8lHYQK7KII0xBWisB+CjqYqxbPkLw=="),
		},
		{
			Data:           []byte("123"),
			HashData:       []byte{120, 216, 4, 93, 104, 74, 189, 46, 236, 233, 35, 117, 143, 60, 215, 129, 72, 157, 243, 164, 142, 18, 120, 152, 36, 102, 1, 127},
			HashDataHex:    []byte("78d8045d684abd2eece923758f3cd781489df3a48e1278982466017f"),
			HashDataBase64: []byte("eNgEXWhKvS7s6SN1jzzXgUid86SOEniYJGYBfw=="),
		},
		{
			Data:           []byte("你好，世界"),
			HashData:       []byte{154, 101, 161, 40, 24, 184, 230, 172, 53, 124, 238, 147, 55, 86, 83, 55, 245, 91, 218, 138, 69, 176, 193, 191, 185, 244, 64, 60},
			HashDataHex:    []byte("9a65a12818b8e6ac357cee9337565337f55bda8a45b0c1bfb9f4403c"),
			HashDataBase64: []byte("mmWhKBi45qw1fO6TN1ZTN/Vb2opFsMG/ufRAPA=="),
		},
	}

	if err := testHash(t.Name(), SHA224, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestSHA256$
func TestSHA256(t *testing.T) {
	testCases := []testCase{
		{
			Data:           []byte(""),
			HashData:       []byte{227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85},
			HashDataHex:    []byte("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			HashDataBase64: []byte("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="),
		},
		{
			Data:           []byte("123"),
			HashData:       []byte{166, 101, 164, 89, 32, 66, 47, 157, 65, 126, 72, 103, 239, 220, 79, 184, 160, 74, 31, 63, 255, 31, 160, 126, 153, 142, 134, 247, 247, 162, 122, 227},
			HashDataHex:    []byte("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"),
			HashDataBase64: []byte("pmWkWSBCL51Bfkhn79xPuKBKHz//H6B+mY6G9/eieuM="),
		},
		{
			Data:           []byte("你好，世界"),
			HashData:       []byte{70, 147, 47, 30, 110, 165, 33, 110, 119, 245, 139, 25, 8, 215, 46, 201, 50, 46, 209, 41, 49, 140, 109, 75, 212, 69, 11, 94, 170, 185, 215, 231},
			HashDataHex:    []byte("46932f1e6ea5216e77f58b1908d72ec9322ed129318c6d4bd4450b5eaab9d7e7"),
			HashDataBase64: []byte("RpMvHm6lIW539YsZCNcuyTIu0SkxjG1L1EULXqq51+c="),
		},
	}

	if err := testHash(t.Name(), SHA256, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestSHA384$
func TestSHA384(t *testing.T) {
	testCases := []testCase{
		{
			Data:           []byte(""),
			HashData:       []byte{56, 176, 96, 167, 81, 172, 150, 56, 76, 217, 50, 126, 177, 177, 227, 106, 33, 253, 183, 17, 20, 190, 7, 67, 76, 12, 199, 191, 99, 246, 225, 218, 39, 78, 222, 191, 231, 111, 101, 251, 213, 26, 210, 241, 72, 152, 185, 91},
			HashDataHex:    []byte("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
			HashDataBase64: []byte("OLBgp1GsljhM2TJ+sbHjaiH9txEUvgdDTAzHv2P24donTt6/529l+9Ua0vFImLlb"),
		},
		{
			Data:           []byte("123"),
			HashData:       []byte{154, 10, 130, 240, 192, 207, 49, 71, 13, 122, 255, 237, 227, 64, 108, 201, 170, 132, 16, 103, 21, 32, 183, 39, 4, 78, 218, 21, 180, 194, 85, 50, 169, 181, 205, 138, 175, 156, 236, 73, 25, 215, 98, 85, 182, 191, 176, 15},
			HashDataHex:    []byte("9a0a82f0c0cf31470d7affede3406cc9aa8410671520b727044eda15b4c25532a9b5cd8aaf9cec4919d76255b6bfb00f"),
			HashDataBase64: []byte("mgqC8MDPMUcNev/t40BsyaqEEGcVILcnBE7aFbTCVTKptc2Kr5zsSRnXYlW2v7AP"),
		},
		{
			Data:           []byte("你好，世界"),
			HashData:       []byte{251, 234, 22, 216, 190, 41, 147, 242, 205, 161, 239, 159, 192, 85, 245, 63, 15, 162, 63, 30, 29, 196, 165, 122, 117, 72, 195, 98, 39, 195, 239, 4, 145, 72, 79, 207, 30, 48, 197, 209, 255, 23, 68, 26, 92, 232, 154, 17},
			HashDataHex:    []byte("fbea16d8be2993f2cda1ef9fc055f53f0fa23f1e1dc4a57a7548c36227c3ef0491484fcf1e30c5d1ff17441a5ce89a11"),
			HashDataBase64: []byte("++oW2L4pk/LNoe+fwFX1Pw+iPx4dxKV6dUjDYifD7wSRSE/PHjDF0f8XRBpc6JoR"),
		},
	}

	if err := testHash(t.Name(), SHA384, testCases); err != nil {
		t.Fatal(err)
	}
}

// go test -v -cover -run=^TestSHA512$
func TestSHA512(t *testing.T) {
	testCases := []testCase{
		{
			Data:           []byte(""),
			HashData:       []byte{207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214, 32, 228, 5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208, 209, 60, 93, 133, 242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49, 189, 71, 65, 122, 129, 165, 56, 50, 122, 249, 39, 218, 62},
			HashDataHex:    []byte("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
			HashDataBase64: []byte("z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="),
		},
		{
			Data:           []byte("123"),
			HashData:       []byte{60, 153, 9, 175, 236, 37, 53, 77, 85, 29, 174, 33, 89, 11, 178, 110, 56, 213, 63, 33, 115, 184, 211, 220, 62, 238, 76, 4, 126, 122, 177, 193, 235, 139, 133, 16, 62, 59, 231, 186, 97, 59, 49, 187, 92, 156, 54, 33, 77, 201, 241, 74, 66, 253, 122, 47, 219, 132, 133, 107, 202, 92, 68, 194},
			HashDataHex:    []byte("3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2"),
			HashDataBase64: []byte("PJkJr+wlNU1VHa4hWQuybjjVPyFzuNPcPu5MBH56scHri4UQPjvnumE7MbtcnDYhTcnxSkL9ei/bhIVrylxEwg=="),
		},
		{
			Data:           []byte("你好，世界"),
			HashData:       []byte{69, 166, 227, 254, 120, 175, 74, 51, 38, 218, 155, 248, 195, 64, 123, 202, 95, 239, 128, 179, 52, 192, 70, 210, 5, 68, 176, 178, 139, 230, 199, 97, 113, 140, 250, 245, 183, 82, 234, 168, 152, 73, 184, 58, 77, 78, 95, 109, 244, 144, 142, 25, 92, 216, 193, 89, 24, 30, 120, 151, 25, 16, 219, 19},
			HashDataHex:    []byte("45a6e3fe78af4a3326da9bf8c3407bca5fef80b334c046d20544b0b28be6c761718cfaf5b752eaa89849b83a4d4e5f6df4908e195cd8c159181e78971910db13"),
			HashDataBase64: []byte("Rabj/nivSjMm2pv4w0B7yl/vgLM0wEbSBUSwsovmx2FxjPr1t1LqqJhJuDpNTl9t9JCOGVzYwVkYHniXGRDbEw=="),
		},
	}

	if err := testHash(t.Name(), SHA512, testCases); err != nil {
		t.Fatal(err)
	}
}
