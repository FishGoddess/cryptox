// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"bytes"
	"slices"
	"testing"
)

type testCase struct {
	Data              []byte
	EncryptData       []byte
	EncryptDataHex    []byte
	EncryptDataBase64 []byte
}

type testRandomReader struct{}

func (testRandomReader) Read(p []byte) (n int, err error) {
	for i := 0; i < len(p); i++ {
		p[i] = 1
	}

	return len(p), nil
}

func newTestPublicKey() PublicKey {
	reader := bytes.NewReader([]byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp6Ap2KrXXMaNmc3K6ZHx
2IPrP4Bq5be1sP/4ASX3AmeuJbOHw+CNAQ/l3tFh7k+aaKMOgsspdtMq72Nd6KpU
a9OW7Jz6btmTohD34gEG/PfMYGGMKA8CxJO+VLtaMed7p4YWW0SjZ3tVdUDGBacQ
IHgDMTC9PWZhKj6d6tATWXI2amqv9rph1TgTq6q0SWRuwD2aYsQL8G0SicxC6uNL
NMw+hAqL2ZP91lRfARHK5sm5p257NWPPabVxWSEFSj6h11CvflWyIimbFPlCqWNv
ViozpBC3EqxuxzGWyF4r87MBp+XNA7JF0P0281eVjcaVtOzqdLN8vRu5/pE3MrWR
EwIDAQAB
-----END PUBLIC KEY-----`))

	publicKey, err := ReadPublicKey(reader)
	if err != nil {
		panic(err)
	}

	return publicKey
}

// go test -v -cover -run=^TestEncryptDecryptPKCS1v15$
func TestEncryptDecryptPKCS1v15(t *testing.T) {
	privateKey := newTestPrivateKey()
	publicKey := newTestPublicKey()

	testCases := []testCase{
		{
			Data:              []byte(""),
			EncryptData:       []byte{116, 242, 43, 134, 99, 44, 254, 137, 141, 79, 25, 122, 116, 221, 33, 96, 98, 244, 87, 125, 98, 109, 108, 84, 77, 195, 236, 156, 53, 182, 149, 206, 127, 200, 196, 60, 107, 48, 158, 215, 245, 177, 47, 197, 102, 116, 39, 76, 206, 55, 19, 32, 199, 254, 96, 0, 237, 156, 213, 200, 198, 78, 28, 110, 103, 8, 177, 211, 58, 215, 159, 252, 26, 122, 230, 78, 197, 219, 93, 8, 164, 72, 191, 25, 127, 54, 108, 22, 245, 188, 66, 155, 239, 1, 145, 209, 147, 37, 170, 38, 16, 210, 247, 191, 83, 22, 26, 148, 46, 124, 56, 12, 24, 36, 128, 80, 36, 58, 99, 104, 222, 236, 163, 212, 151, 30, 83, 117, 177, 175, 227, 251, 145, 219, 14, 7, 53, 224, 21, 193, 56, 180, 8, 199, 189, 211, 19, 42, 75, 216, 176, 164, 88, 101, 87, 219, 92, 222, 164, 13, 169, 153, 236, 23, 104, 132, 203, 245, 150, 247, 177, 241, 124, 220, 79, 159, 152, 213, 222, 144, 70, 100, 44, 36, 86, 36, 198, 224, 175, 252, 252, 113, 37, 253, 140, 184, 180, 155, 236, 236, 155, 138, 65, 233, 51, 93, 50, 122, 194, 253, 251, 3, 172, 161, 118, 130, 106, 71, 150, 68, 174, 136, 242, 164, 0, 83, 232, 128, 165, 138, 203, 54, 157, 239, 36, 254, 174, 105, 100, 11, 193, 22, 184, 233, 198, 247, 167, 187, 6, 188, 124, 186, 234, 54, 79, 242},
			EncryptDataHex:    []byte("74f22b86632cfe898d4f197a74dd216062f4577d626d6c544dc3ec9c35b695ce7fc8c43c6b309ed7f5b12fc56674274cce371320c7fe6000ed9cd5c8c64e1c6e6708b1d33ad79ffc1a7ae64ec5db5d08a448bf197f366c16f5bc429bef0191d19325aa2610d2f7bf53161a942e7c380c18248050243a6368deeca3d4971e5375b1afe3fb91db0e0735e015c138b408c7bdd3132a4bd8b0a4586557db5cdea40da999ec176884cbf596f7b1f17cdc4f9f98d5de9046642c245624c6e0affcfc7125fd8cb8b49becec9b8a41e9335d327ac2fdfb03aca176826a479644ae88f2a40053e880a58acb369def24feae69640bc116b8e9c6f7a7bb06bc7cbaea364ff2"),
			EncryptDataBase64: []byte("dPIrhmMs/omNTxl6dN0hYGL0V31ibWxUTcPsnDW2lc5/yMQ8azCe1/WxL8VmdCdMzjcTIMf+YADtnNXIxk4cbmcIsdM615/8GnrmTsXbXQikSL8ZfzZsFvW8QpvvAZHRkyWqJhDS979TFhqULnw4DBgkgFAkOmNo3uyj1JceU3Wxr+P7kdsOBzXgFcE4tAjHvdMTKkvYsKRYZVfbXN6kDamZ7BdohMv1lvex8XzcT5+Y1d6QRmQsJFYkxuCv/PxxJf2MuLSb7OybikHpM10yesL9+wOsoXaCakeWRK6I8qQAU+iApYrLNp3vJP6uaWQLwRa46cb3p7sGvHy66jZP8g=="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{65, 112, 83, 139, 223, 173, 140, 44, 39, 240, 29, 168, 95, 0, 100, 219, 11, 167, 173, 23, 10, 160, 41, 193, 242, 188, 167, 55, 123, 173, 114, 85, 5, 99, 5, 52, 27, 85, 52, 123, 175, 181, 56, 57, 30, 96, 241, 153, 77, 178, 246, 166, 192, 90, 174, 66, 1, 206, 64, 247, 158, 239, 146, 184, 206, 43, 109, 140, 51, 65, 228, 237, 172, 105, 83, 106, 18, 199, 216, 22, 114, 76, 198, 88, 103, 7, 184, 133, 33, 108, 177, 185, 17, 164, 168, 17, 167, 145, 0, 243, 100, 196, 194, 164, 254, 235, 72, 254, 37, 255, 68, 0, 243, 222, 88, 115, 81, 22, 41, 155, 211, 61, 226, 10, 4, 141, 106, 101, 79, 24, 90, 36, 225, 141, 178, 1, 8, 233, 179, 68, 43, 96, 111, 200, 152, 255, 5, 11, 189, 74, 200, 244, 181, 26, 43, 26, 137, 220, 141, 76, 167, 0, 46, 61, 73, 85, 67, 16, 214, 192, 109, 237, 186, 193, 34, 16, 88, 154, 161, 113, 222, 188, 146, 250, 114, 82, 215, 35, 42, 162, 2, 204, 86, 112, 143, 156, 64, 255, 31, 126, 111, 131, 112, 208, 28, 68, 118, 194, 190, 22, 127, 77, 101, 28, 188, 254, 198, 157, 202, 5, 126, 209, 47, 211, 27, 31, 72, 56, 137, 97, 96, 80, 115, 7, 0, 190, 104, 91, 81, 103, 220, 139, 209, 87, 156, 70, 67, 17, 245, 149, 58, 253, 39, 85, 126, 19},
			EncryptDataHex:    []byte("4170538bdfad8c2c27f01da85f0064db0ba7ad170aa029c1f2bca7377bad7255056305341b55347bafb538391e60f1994db2f6a6c05aae4201ce40f79eef92b8ce2b6d8c3341e4edac69536a12c7d816724cc6586707b885216cb1b911a4a811a79100f364c4c2a4feeb48fe25ff4400f3de58735116299bd33de20a048d6a654f185a24e18db20108e9b3442b606fc898ff050bbd4ac8f4b51a2b1a89dc8d4ca7002e3d49554310d6c06dedbac12210589aa171debc92fa7252d7232aa202cc56708f9c40ff1f7e6f8370d01c4476c2be167f4d651cbcfec69dca057ed12fd31b1f483889616050730700be685b5167dc8bd1579c464311f5953afd27557e13"),
			EncryptDataBase64: []byte("QXBTi9+tjCwn8B2oXwBk2wunrRcKoCnB8rynN3utclUFYwU0G1U0e6+1ODkeYPGZTbL2psBarkIBzkD3nu+SuM4rbYwzQeTtrGlTahLH2BZyTMZYZwe4hSFssbkRpKgRp5EA82TEwqT+60j+Jf9EAPPeWHNRFimb0z3iCgSNamVPGFok4Y2yAQjps0QrYG/ImP8FC71KyPS1GisaidyNTKcALj1JVUMQ1sBt7brBIhBYmqFx3ryS+nJS1yMqogLMVnCPnED/H35vg3DQHER2wr4Wf01lHLz+xp3KBX7RL9MbH0g4iWFgUHMHAL5oW1Fn3IvRV5xGQxH1lTr9J1V+Ew=="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{77, 240, 180, 40, 245, 65, 99, 253, 77, 0, 80, 90, 201, 188, 155, 206, 95, 249, 121, 236, 131, 155, 144, 213, 59, 108, 56, 230, 202, 241, 138, 154, 80, 173, 120, 123, 149, 255, 65, 90, 31, 93, 201, 82, 249, 121, 22, 50, 73, 21, 179, 131, 169, 7, 139, 101, 26, 59, 161, 194, 48, 233, 57, 234, 210, 81, 193, 253, 18, 15, 228, 4, 89, 28, 11, 51, 157, 39, 231, 124, 100, 56, 114, 122, 65, 140, 8, 60, 155, 112, 31, 64, 79, 15, 105, 99, 107, 125, 152, 42, 5, 44, 48, 104, 73, 238, 229, 236, 168, 86, 151, 138, 236, 38, 133, 56, 150, 181, 202, 247, 114, 233, 95, 194, 137, 82, 170, 0, 208, 78, 116, 241, 177, 60, 196, 212, 163, 35, 215, 227, 189, 146, 160, 171, 246, 80, 168, 231, 235, 101, 206, 101, 137, 233, 96, 82, 148, 212, 104, 134, 131, 61, 28, 25, 240, 120, 59, 30, 44, 179, 126, 149, 5, 5, 152, 61, 79, 52, 203, 157, 90, 233, 236, 135, 82, 225, 51, 252, 224, 183, 122, 175, 53, 200, 232, 58, 19, 186, 171, 223, 11, 186, 12, 128, 57, 93, 232, 56, 63, 78, 238, 108, 199, 248, 82, 161, 73, 33, 124, 158, 175, 176, 5, 99, 250, 157, 143, 11, 12, 38, 57, 226, 234, 12, 212, 29, 107, 251, 179, 39, 110, 251, 109, 185, 242, 23, 232, 133, 173, 84, 129, 63, 61, 253, 56, 175},
			EncryptDataHex:    []byte("4df0b428f54163fd4d00505ac9bc9bce5ff979ec839b90d53b6c38e6caf18a9a50ad787b95ff415a1f5dc952f97916324915b383a9078b651a3ba1c230e939ead251c1fd120fe404591c0b339d27e77c6438727a418c083c9b701f404f0f69636b7d982a052c306849eee5eca856978aec26853896b5caf772e95fc28952aa00d04e74f1b13cc4d4a323d7e3bd92a0abf650a8e7eb65ce6589e9605294d46886833d1c19f0783b1e2cb37e950505983d4f34cb9d5ae9ec8752e133fce0b77aaf35c8e83a13baabdf0bba0c80395de8383f4eee6cc7f852a149217c9eafb00563fa9d8f0b0c2639e2ea0cd41d6bfbb3276efb6db9f217e885ad54813f3dfd38af"),
			EncryptDataBase64: []byte("TfC0KPVBY/1NAFBaybybzl/5eeyDm5DVO2w45srxippQrXh7lf9BWh9dyVL5eRYySRWzg6kHi2UaO6HCMOk56tJRwf0SD+QEWRwLM50n53xkOHJ6QYwIPJtwH0BPD2lja32YKgUsMGhJ7uXsqFaXiuwmhTiWtcr3culfwolSqgDQTnTxsTzE1KMj1+O9kqCr9lCo5+tlzmWJ6WBSlNRohoM9HBnweDseLLN+lQUFmD1PNMudWunsh1LhM/zgt3qvNcjoOhO6q98LugyAOV3oOD9O7mzH+FKhSSF8nq+wBWP6nY8LDCY54uoM1B1r+7MnbvttufIX6IWtVIE/Pf04rw=="),
		},
	}

	random := testRandomReader{}
	for _, testCase := range testCases {
		// None
		encrypted, err := publicKey.EncryptPKCS1v15(testCase.Data, WithRandom(random))
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(encrypted, testCase.EncryptData) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, encrypted, testCase.EncryptData)
		}

		decrypted, err := privateKey.DecryptPKCS1v15(encrypted, WithRandom(random))
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(decrypted, testCase.Data) {
			t.Fatalf("encrypted %q: got %+v != expect %+v", encrypted, decrypted, testCase.Data)
		}

		// Hex
		encrypted, err = publicKey.EncryptPKCS1v15(testCase.Data, WithHex(), WithRandom(random))
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(encrypted, testCase.EncryptDataHex) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, encrypted, testCase.EncryptDataHex)
		}

		decrypted, err = privateKey.DecryptPKCS1v15(encrypted, WithHex(), WithRandom(random))
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(decrypted, testCase.Data) {
			t.Fatalf("encrypted %q: got %+v != expect %+v", encrypted, decrypted, testCase.Data)
		}

		// Base64
		encrypted, err = publicKey.EncryptPKCS1v15(testCase.Data, WithBase64(), WithRandom(random))
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(encrypted, testCase.EncryptDataBase64) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, encrypted, testCase.EncryptDataBase64)
		}

		decrypted, err = privateKey.DecryptPKCS1v15(encrypted, WithBase64(), WithRandom(random))
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(decrypted, testCase.Data) {
			t.Fatalf("encrypted %q: got %+v != expect %+v", encrypted, decrypted, testCase.Data)
		}
	}
}

// go test -v -cover -run=^TestEncryptDecryptOAEP$
func TestEncryptDecryptOAEP(t *testing.T) {
	privateKey := newTestPrivateKey()
	publicKey := newTestPublicKey()

	testCases := []testCase{
		{
			Data:              []byte(""),
			EncryptData:       []byte{93, 21, 253, 18, 191, 140, 145, 9, 36, 234, 228, 96, 42, 8, 3, 111, 186, 171, 32, 0, 227, 220, 31, 173, 88, 184, 250, 55, 71, 16, 193, 185, 37, 16, 140, 70, 2, 82, 92, 146, 182, 1, 168, 184, 83, 227, 21, 123, 238, 157, 73, 142, 23, 30, 240, 129, 242, 6, 216, 247, 93, 7, 7, 112, 214, 166, 171, 193, 246, 163, 43, 146, 87, 246, 235, 254, 40, 130, 72, 190, 154, 52, 162, 23, 204, 143, 217, 139, 62, 123, 142, 140, 124, 152, 38, 213, 189, 94, 205, 165, 221, 174, 213, 160, 96, 218, 71, 121, 187, 105, 2, 99, 226, 97, 109, 122, 141, 73, 255, 252, 123, 212, 83, 154, 190, 213, 107, 29, 163, 67, 122, 169, 38, 220, 29, 149, 181, 106, 92, 126, 227, 193, 129, 225, 203, 153, 157, 165, 252, 68, 132, 77, 131, 109, 77, 100, 178, 182, 155, 5, 250, 89, 203, 215, 59, 82, 63, 46, 21, 49, 87, 190, 154, 115, 49, 98, 26, 222, 113, 186, 18, 205, 132, 74, 125, 141, 215, 179, 2, 211, 68, 72, 119, 40, 107, 232, 75, 120, 60, 146, 176, 39, 255, 124, 199, 195, 77, 68, 93, 227, 174, 17, 165, 139, 91, 84, 21, 252, 124, 199, 74, 171, 223, 17, 144, 193, 101, 151, 195, 147, 163, 96, 174, 37, 6, 97, 48, 216, 116, 159, 250, 165, 140, 235, 27, 45, 136, 152, 96, 163, 4, 207, 57, 245, 102, 204},
			EncryptDataHex:    []byte("5d15fd12bf8c910924eae4602a08036fbaab2000e3dc1fad58b8fa374710c1b925108c4602525c92b601a8b853e3157bee9d498e171ef081f206d8f75d070770d6a6abc1f6a32b9257f6ebfe288248be9a34a217cc8fd98b3e7b8e8c7c9826d5bd5ecda5ddaed5a060da4779bb690263e2616d7a8d49fffc7bd4539abed56b1da3437aa926dc1d95b56a5c7ee3c181e1cb999da5fc44844d836d4d64b2b69b05fa59cbd73b523f2e153157be9a7331621ade71ba12cd844a7d8dd7b302d3444877286be84b783c92b027ff7cc7c34d445de3ae11a58b5b5415fc7cc74aabdf1190c16597c393a360ae25066130d8749ffaa58ceb1b2d889860a304cf39f566cc"),
			EncryptDataBase64: []byte("XRX9Er+MkQkk6uRgKggDb7qrIADj3B+tWLj6N0cQwbklEIxGAlJckrYBqLhT4xV77p1Jjhce8IHyBtj3XQcHcNamq8H2oyuSV/br/iiCSL6aNKIXzI/Ziz57jox8mCbVvV7Npd2u1aBg2kd5u2kCY+JhbXqNSf/8e9RTmr7Vax2jQ3qpJtwdlbVqXH7jwYHhy5mdpfxEhE2DbU1ksrabBfpZy9c7Uj8uFTFXvppzMWIa3nG6Es2ESn2N17MC00RIdyhr6Et4PJKwJ/98x8NNRF3jrhGli1tUFfx8x0qr3xGQwWWXw5OjYK4lBmEw2HSf+qWM6xstiJhgowTPOfVmzA=="),
		},
		{
			Data:              []byte("123"),
			EncryptData:       []byte{131, 48, 98, 101, 212, 117, 12, 31, 19, 157, 186, 200, 121, 122, 207, 186, 233, 45, 145, 134, 199, 150, 107, 88, 154, 185, 54, 141, 206, 210, 1, 101, 4, 120, 249, 147, 36, 31, 39, 27, 168, 136, 164, 32, 220, 185, 6, 221, 135, 208, 145, 214, 99, 126, 147, 7, 193, 159, 231, 170, 232, 12, 2, 67, 223, 103, 96, 190, 32, 40, 198, 247, 151, 247, 112, 13, 72, 223, 20, 3, 20, 6, 152, 0, 252, 22, 228, 254, 182, 180, 149, 83, 168, 194, 203, 6, 192, 135, 145, 166, 171, 44, 121, 19, 133, 199, 41, 192, 209, 194, 241, 218, 100, 172, 121, 250, 18, 19, 152, 109, 51, 164, 175, 208, 51, 239, 140, 219, 138, 75, 3, 61, 73, 123, 182, 3, 104, 86, 106, 244, 30, 145, 228, 233, 202, 63, 142, 157, 88, 175, 230, 157, 93, 181, 199, 240, 111, 132, 147, 215, 31, 177, 146, 55, 130, 224, 218, 43, 87, 88, 233, 150, 109, 33, 72, 37, 236, 41, 220, 72, 237, 1, 230, 34, 33, 39, 254, 38, 245, 121, 54, 192, 38, 226, 245, 43, 226, 190, 194, 200, 156, 182, 143, 197, 22, 92, 223, 29, 143, 148, 79, 25, 22, 245, 235, 129, 22, 162, 194, 167, 188, 2, 249, 214, 210, 142, 61, 151, 224, 84, 147, 212, 67, 252, 224, 67, 44, 34, 10, 207, 55, 235, 237, 198, 199, 229, 122, 150, 178, 206, 93, 79, 63, 252, 14, 0},
			EncryptDataHex:    []byte("83306265d4750c1f139dbac8797acfbae92d9186c7966b589ab9368dced201650478f993241f271ba888a420dcb906dd87d091d6637e9307c19fe7aae80c0243df6760be2028c6f797f7700d48df140314069800fc16e4feb6b49553a8c2cb06c08791a6ab2c791385c729c0d1c2f1da64ac79fa1213986d33a4afd033ef8cdb8a4b033d497bb60368566af41e91e4e9ca3f8e9d58afe69d5db5c7f06f8493d71fb1923782e0da2b5758e9966d214825ec29dc48ed01e6222127fe26f57936c026e2f52be2bec2c89cb68fc5165cdf1d8f944f1916f5eb8116a2c2a7bc02f9d6d28e3d97e05493d443fce0432c220acf37ebedc6c7e57a96b2ce5d4f3ffc0e00"),
			EncryptDataBase64: []byte("gzBiZdR1DB8TnbrIeXrPuuktkYbHlmtYmrk2jc7SAWUEePmTJB8nG6iIpCDcuQbdh9CR1mN+kwfBn+eq6AwCQ99nYL4gKMb3l/dwDUjfFAMUBpgA/Bbk/ra0lVOowssGwIeRpqsseROFxynA0cLx2mSsefoSE5htM6Sv0DPvjNuKSwM9SXu2A2hWavQekeTpyj+OnViv5p1dtcfwb4ST1x+xkjeC4NorV1jplm0hSCXsKdxI7QHmIiEn/ib1eTbAJuL1K+K+wsicto/FFlzfHY+UTxkW9euBFqLCp7wC+dbSjj2X4FST1EP84EMsIgrPN+vtxsflepayzl1PP/wOAA=="),
		},
		{
			Data:              []byte("你好，世界"),
			EncryptData:       []byte{74, 48, 16, 184, 244, 162, 46, 60, 78, 194, 73, 221, 250, 253, 69, 8, 197, 241, 219, 80, 128, 75, 110, 216, 91, 109, 10, 139, 159, 240, 43, 108, 69, 251, 114, 158, 212, 19, 186, 20, 18, 161, 160, 5, 214, 69, 101, 200, 198, 89, 127, 226, 132, 1, 118, 52, 29, 27, 16, 31, 230, 248, 64, 123, 18, 115, 17, 1, 175, 199, 88, 213, 127, 73, 75, 33, 106, 242, 23, 19, 136, 0, 246, 187, 119, 234, 156, 86, 32, 26, 23, 203, 109, 222, 129, 149, 162, 89, 13, 92, 172, 240, 218, 7, 65, 0, 146, 162, 95, 93, 119, 245, 100, 149, 204, 130, 199, 169, 245, 49, 80, 19, 143, 129, 4, 21, 29, 244, 172, 57, 81, 63, 84, 86, 141, 160, 154, 63, 149, 200, 207, 108, 215, 186, 18, 44, 136, 70, 125, 171, 165, 11, 78, 105, 57, 102, 169, 61, 14, 228, 226, 18, 153, 18, 93, 206, 117, 149, 186, 5, 98, 161, 251, 116, 134, 162, 93, 55, 225, 11, 185, 44, 159, 241, 198, 183, 228, 249, 51, 247, 85, 139, 211, 82, 96, 106, 250, 210, 106, 96, 30, 239, 63, 224, 211, 202, 44, 41, 189, 165, 90, 240, 124, 134, 32, 245, 99, 54, 233, 231, 177, 191, 50, 195, 102, 245, 235, 182, 67, 132, 108, 112, 157, 221, 84, 187, 254, 2, 223, 11, 120, 195, 181, 221, 61, 232, 166, 158, 122, 60, 186, 255, 71, 37, 132, 101},
			EncryptDataHex:    []byte("4a3010b8f4a22e3c4ec249ddfafd4508c5f1db50804b6ed85b6d0a8b9ff02b6c45fb729ed413ba1412a1a005d64565c8c6597fe2840176341d1b101fe6f8407b12731101afc758d57f494b216af217138800f6bb77ea9c56201a17cb6dde8195a2590d5cacf0da07410092a25f5d77f56495cc82c7a9f53150138f8104151df4ac39513f54568da09a3f95c8cf6cd7ba122c88467daba50b4e693966a93d0ee4e21299125dce7595ba0562a1fb7486a25d37e10bb92c9ff1c6b7e4f933f7558bd352606afad26a601eef3fe0d3ca2c29bda55af07c8620f56336e9e7b1bf32c366f5ebb643846c709ddd54bbfe02df0b78c3b5dd3de8a69e7a3cbaff47258465"),
			EncryptDataBase64: []byte("SjAQuPSiLjxOwknd+v1FCMXx21CAS27YW20Ki5/wK2xF+3Ke1BO6FBKhoAXWRWXIxll/4oQBdjQdGxAf5vhAexJzEQGvx1jVf0lLIWryFxOIAPa7d+qcViAaF8tt3oGVolkNXKzw2gdBAJKiX1139WSVzILHqfUxUBOPgQQVHfSsOVE/VFaNoJo/lcjPbNe6EiyIRn2rpQtOaTlmqT0O5OISmRJdznWVugVioft0hqJdN+ELuSyf8ca35Pkz91WL01JgavrSamAe7z/g08osKb2lWvB8hiD1Yzbp57G/MsNm9eu2Q4RscJ3dVLv+At8LeMO13T3opp56PLr/RyWEZQ=="),
		},
	}

	label := []byte("label")
	random := testRandomReader{}
	for _, testCase := range testCases {
		// None
		encrypted, err := publicKey.EncryptOAEP(testCase.Data, label, WithRandom(random))
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(encrypted, testCase.EncryptData) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, encrypted, testCase.EncryptData)
		}

		decrypted, err := privateKey.DecryptOAEP(encrypted, label, WithRandom(random))
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(decrypted, testCase.Data) {
			t.Fatalf("encrypted %q: got %+v != expect %+v", encrypted, decrypted, testCase.Data)
		}

		// Hex
		encrypted, err = publicKey.EncryptOAEP(testCase.Data, label, WithHex(), WithRandom(random))
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(encrypted, testCase.EncryptDataHex) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, encrypted, testCase.EncryptDataHex)
		}

		decrypted, err = privateKey.DecryptOAEP(encrypted, label, WithHex(), WithRandom(random))
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(decrypted, testCase.Data) {
			t.Fatalf("encrypted %q: got %+v != expect %+v", encrypted, decrypted, testCase.Data)
		}

		// Base64
		encrypted, err = publicKey.EncryptOAEP(testCase.Data, label, WithBase64(), WithRandom(random))
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(encrypted, testCase.EncryptDataBase64) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, encrypted, testCase.EncryptDataBase64)
		}

		decrypted, err = privateKey.DecryptOAEP(encrypted, label, WithBase64(), WithRandom(random))
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(decrypted, testCase.Data) {
			t.Fatalf("encrypted %q: got %+v != expect %+v", encrypted, decrypted, testCase.Data)
		}
	}
}

// go test -v -cover -run=^TestDecryptPKCS1v15SessionKey$
func TestDecryptPKCS1v15SessionKey(t *testing.T) {
	privateKey := newTestPrivateKey()
	publicKey := newTestPublicKey()

	sessionKey := []byte("12345678876543211234567887654321")
	random := testRandomReader{}

	encrypt, err := publicKey.EncryptPKCS1v15(sessionKey, WithRandom(random))
	if err != nil {
		t.Fatal(err)
	}

	gotSessionKey := make([]byte, len(sessionKey))

	err = privateKey.DecryptPKCS1v15SessionKey(encrypt, gotSessionKey, WithRandom(random))
	if err != nil {
		panic(err)
	}

	if !slices.Equal(sessionKey, gotSessionKey) {
		t.Fatalf("got %+v != expect %+v", sessionKey, gotSessionKey)
	}
}
