// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"testing"
)

type encryptTestCase struct {
	Data              []byte
	EncryptData       []byte
	EncryptDataHex    []byte
	EncryptDataBase64 []byte
}

type signTestCase struct {
	Data           []byte
	SignData       []byte
	SignDataHex    []byte
	SignDataBase64 []byte
}

type testRandomReader struct{}

func (testRandomReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 1
	}

	return len(p), nil
}

func newTestPrivateKey() PrivateKey {
	reader := bytes.NewReader([]byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCnoCnYqtdcxo2Z
zcrpkfHYg+s/gGrlt7Ww//gBJfcCZ64ls4fD4I0BD+Xe0WHuT5poow6Cyyl20yrv
Y13oqlRr05bsnPpu2ZOiEPfiAQb898xgYYwoDwLEk75Uu1ox53unhhZbRKNne1V1
QMYFpxAgeAMxML09ZmEqPp3q0BNZcjZqaq/2umHVOBOrqrRJZG7APZpixAvwbRKJ
zELq40s0zD6ECovZk/3WVF8BEcrmybmnbns1Y89ptXFZIQVKPqHXUK9+VbIiKZsU
+UKpY29WKjOkELcSrG7HMZbIXivzswGn5c0DskXQ/TbzV5WNxpW07Op0s3y9G7n+
kTcytZETAgMBAAECggEACpRE/9aBwr+0lnU9WLIW0Y47LdCk2ScChw9omhNI0cnf
B6RwgvAW8MRi7XCeiHlVVURGjqz+ysU3YPtkT7esSKUxJxwd1sV8QqQP2PTX+ZA0
Fw3LrYg2VFdqEZPvdICCYTIeaBfeuOcOSi5Shm8i8+xPG0QoYAnS7mUcTK0MLj65
FYcb1p7rteeqpQwKqekaAEqOo084Nbs10++ltct3wM4xOvEFJubdMUj6kruOVwG5
onuyONTWQ9U1akSRwlx1HnafieTG/Rsvx+6FT4wAgioZy3JKlWsLckI0K5zi/YSz
Z0ZeqdtGLI7JbYIKv+H+zeLv0mPErwOXJk0qm3b6eQKBgQDJVMYzwB1BIVU545dz
8+YX69WfFVjH9RSJ+9monq6fu0QW6s2qH4O8DCKqG5fuSAXPVzYvVrEDV4KGsyPG
m0uQteM5om7ICIQVvewxBiaDX0bvFwiK7gfzdLVMgYirrkxZUQ4NgGTRScAP2ysm
sOn52Om5ZK5JZ3v8C/aQU/D5CQKBgQDVJGcDV7XlOVMptAVICEP4G+jg2fS9ORlz
TkgpK8sw1l1P6eO9WU2TrOh8UCQFntVe5YwgzQuBK4PJACsbHqx1Xww57MI1dlIQ
p2vP6dFmVlneIrcHXZ4QRQug6Envp03Smnbzf9clDCAtZkt3gGDc2r0yxn8AY6rE
+q6mITHMOwKBgQC7ernmzutvDv8yHQGX9HM7q10N+u7lpQ8vPtt87edmzxekz5oc
5aPipNpS1ccxGNhwL6JBitTja8YccQzLkSlY5EdoEB5hH60AIg+jxzpt83c2hZhq
5yV4TCHX0HfYh0KJmbUgVYOMcMTs/wa7zNrU0m0zOtIhgMAwAWPlGoW3IQKBgHSs
l6NRySVwiuCiRd3XgHV5ubIUPY+ziQYAjSnUakcSoUPUkbEeCIRVO3KJYB6fgseO
unVeKPUNf/dwmygeU2Nwoz22J92iJmwtaawHn3P4wvsBX9WtXpAja6kqXwbMO6KU
oZbLnVcPWzHe9GK3KM7dAoKf+/eXl2x6mU4hj6PvAoGBALKTzLcqAr7n+TqcRAJU
nm44K4zj52Nj0lpritovFbP1EiVoj07AFqFULE3aHMeGKwe+aNxz5JTSHPaP6aa9
iD4CVoJzQ41OimqHnnRSgy3g+ylk7plLk/M0rE+6Ev945Xv8vGOGci6KgkBpOx37
/yglpQbyju+BbRvq9gDfLuKX
-----END PRIVATE KEY-----`))

	privateKey, err := ReadPrivateKey(reader)
	if err != nil {
		panic(err)
	}

	return privateKey
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

	testCases := []encryptTestCase{
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

	testCases := []encryptTestCase{
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

// go test -v -cover -run=^TestSignVerifyPKCS1v15$
func TestSignVerifyPKCS1v15(t *testing.T) {
	privateKey := newTestPrivateKey()
	publicKey := newTestPublicKey()

	testCases := []signTestCase{
		{
			Data:           []byte(""),
			SignData:       []byte{129, 179, 114, 121, 197, 185, 134, 59, 90, 166, 224, 37, 174, 125, 153, 232, 105, 240, 59, 0, 240, 138, 96, 226, 197, 33, 49, 46, 93, 207, 75, 41, 6, 114, 86, 167, 171, 119, 149, 211, 8, 92, 254, 93, 87, 253, 118, 93, 32, 37, 217, 71, 18, 253, 7, 244, 156, 214, 224, 132, 80, 137, 157, 223, 51, 22, 194, 24, 241, 249, 118, 61, 62, 132, 174, 169, 225, 186, 219, 93, 208, 253, 63, 53, 88, 180, 138, 207, 34, 239, 23, 140, 107, 174, 18, 123, 62, 144, 78, 95, 37, 170, 143, 231, 27, 164, 95, 248, 136, 104, 124, 9, 10, 126, 252, 83, 132, 129, 29, 54, 216, 55, 67, 87, 193, 25, 50, 112, 1, 199, 234, 36, 52, 109, 80, 250, 140, 153, 87, 174, 45, 170, 15, 148, 176, 239, 132, 77, 160, 44, 18, 192, 19, 248, 131, 76, 213, 39, 205, 33, 185, 73, 37, 111, 48, 250, 129, 17, 48, 222, 63, 225, 233, 25, 7, 78, 215, 22, 168, 72, 115, 209, 68, 18, 44, 192, 77, 64, 249, 206, 25, 199, 90, 157, 159, 49, 65, 207, 135, 203, 228, 4, 20, 171, 232, 10, 39, 221, 112, 170, 116, 67, 2, 35, 188, 175, 185, 67, 137, 41, 152, 172, 247, 203, 216, 60, 108, 74, 66, 150, 29, 235, 220, 203, 1, 86, 60, 218, 16, 249, 117, 249, 57, 53, 53, 89, 34, 3, 183, 220, 129, 61, 220, 100, 30, 5},
			SignDataHex:    []byte("81b37279c5b9863b5aa6e025ae7d99e869f03b00f08a60e2c521312e5dcf4b29067256a7ab7795d3085cfe5d57fd765d2025d94712fd07f49cd6e08450899ddf3316c218f1f9763d3e84aea9e1badb5dd0fd3f3558b48acf22ef178c6bae127b3e904e5f25aa8fe71ba45ff888687c090a7efc5384811d36d8374357c119327001c7ea24346d50fa8c9957ae2daa0f94b0ef844da02c12c013f8834cd527cd21b949256f30fa811130de3fe1e919074ed716a84873d144122cc04d40f9ce19c75a9d9f3141cf87cbe40414abe80a27dd70aa74430223bcafb943892998acf7cbd83c6c4a42961debdccb01563cda10f975f9393535592203b7dc813ddc641e05"),
			SignDataBase64: []byte("gbNyecW5hjtapuAlrn2Z6GnwOwDwimDixSExLl3PSykGclanq3eV0whc/l1X/XZdICXZRxL9B/Sc1uCEUImd3zMWwhjx+XY9PoSuqeG6213Q/T81WLSKzyLvF4xrrhJ7PpBOXyWqj+cbpF/4iGh8CQp+/FOEgR022DdDV8EZMnABx+okNG1Q+oyZV64tqg+UsO+ETaAsEsAT+INM1SfNIblJJW8w+oERMN4/4ekZB07XFqhIc9FEEizATUD5zhnHWp2fMUHPh8vkBBSr6Aon3XCqdEMCI7yvuUOJKZis98vYPGxKQpYd69zLAVY82hD5dfk5NTVZIgO33IE93GQeBQ=="),
		},
		{
			Data:           []byte("123"),
			SignData:       []byte{83, 42, 239, 63, 196, 167, 59, 217, 168, 150, 243, 79, 72, 131, 50, 55, 253, 221, 0, 157, 120, 34, 147, 108, 134, 247, 37, 105, 179, 237, 198, 114, 150, 78, 42, 218, 7, 222, 113, 145, 30, 52, 203, 170, 14, 250, 103, 189, 70, 232, 0, 59, 255, 40, 44, 254, 170, 219, 117, 119, 5, 100, 150, 124, 221, 131, 203, 146, 173, 192, 158, 238, 64, 240, 6, 107, 197, 219, 173, 201, 131, 121, 58, 69, 194, 43, 104, 13, 175, 115, 144, 15, 232, 23, 76, 121, 156, 95, 128, 74, 127, 166, 222, 202, 197, 102, 146, 69, 149, 56, 62, 64, 238, 50, 225, 96, 188, 10, 182, 245, 35, 8, 172, 114, 66, 84, 15, 171, 226, 64, 184, 90, 180, 101, 231, 218, 245, 127, 217, 127, 11, 97, 225, 120, 199, 209, 250, 164, 149, 22, 235, 180, 185, 206, 72, 151, 204, 81, 172, 99, 41, 209, 192, 24, 21, 20, 168, 34, 198, 160, 160, 179, 223, 105, 179, 29, 240, 233, 130, 138, 100, 109, 4, 240, 146, 58, 65, 215, 153, 231, 138, 185, 20, 49, 68, 5, 215, 166, 35, 63, 183, 236, 1, 173, 106, 123, 127, 4, 243, 15, 136, 35, 207, 196, 30, 142, 72, 80, 139, 176, 87, 122, 139, 244, 44, 181, 153, 174, 173, 155, 255, 216, 138, 251, 21, 78, 126, 196, 218, 87, 150, 115, 22, 131, 138, 103, 33, 141, 200, 53, 58, 32, 177, 20, 130, 12},
			SignDataHex:    []byte("532aef3fc4a73bd9a896f34f48833237fddd009d7822936c86f72569b3edc672964e2ada07de71911e34cbaa0efa67bd46e8003bff282cfeaadb75770564967cdd83cb92adc09eee40f0066bc5dbadc983793a45c22b680daf73900fe8174c799c5f804a7fa6decac566924595383e40ee32e160bc0ab6f52308ac7242540fabe240b85ab465e7daf57fd97f0b61e178c7d1faa49516ebb4b9ce4897cc51ac6329d1c0181514a822c6a0a0b3df69b31df0e9828a646d04f0923a41d799e78ab914314405d7a6233fb7ec01ad6a7b7f04f30f8823cfc41e8e48508bb0577a8bf42cb599aead9bffd88afb154e7ec4da57967316838a67218dc8353a20b114820c"),
			SignDataBase64: []byte("UyrvP8SnO9molvNPSIMyN/3dAJ14IpNshvclabPtxnKWTiraB95xkR40y6oO+me9RugAO/8oLP6q23V3BWSWfN2Dy5KtwJ7uQPAGa8XbrcmDeTpFwitoDa9zkA/oF0x5nF+ASn+m3srFZpJFlTg+QO4y4WC8Crb1IwisckJUD6viQLhatGXn2vV/2X8LYeF4x9H6pJUW67S5zkiXzFGsYynRwBgVFKgixqCgs99psx3w6YKKZG0E8JI6QdeZ54q5FDFEBdemIz+37AGtant/BPMPiCPPxB6OSFCLsFd6i/QstZmurZv/2Ir7FU5+xNpXlnMWg4pnIY3INTogsRSCDA=="),
		},
		{
			Data:           []byte("你好，世界"),
			SignData:       []byte{91, 171, 10, 72, 166, 48, 201, 74, 31, 142, 144, 115, 173, 245, 134, 109, 54, 46, 104, 83, 150, 137, 229, 141, 115, 32, 203, 220, 105, 124, 63, 142, 245, 251, 228, 202, 255, 170, 46, 62, 219, 191, 209, 157, 17, 65, 16, 15, 197, 14, 169, 152, 157, 20, 41, 202, 215, 64, 114, 180, 235, 21, 20, 149, 119, 68, 52, 2, 164, 117, 175, 110, 154, 29, 253, 182, 114, 186, 96, 27, 62, 128, 181, 104, 23, 182, 199, 218, 118, 52, 1, 229, 62, 58, 46, 84, 75, 88, 190, 183, 110, 246, 163, 255, 100, 140, 164, 109, 241, 236, 139, 230, 233, 123, 156, 172, 33, 191, 122, 29, 101, 124, 43, 47, 235, 96, 21, 165, 71, 110, 170, 117, 179, 253, 60, 211, 249, 6, 198, 68, 181, 42, 254, 178, 222, 182, 154, 249, 152, 108, 91, 127, 140, 159, 219, 233, 157, 167, 82, 196, 115, 254, 190, 89, 91, 150, 123, 16, 70, 198, 214, 13, 88, 73, 144, 67, 208, 143, 107, 60, 51, 149, 17, 1, 236, 196, 156, 142, 58, 109, 231, 207, 150, 26, 29, 54, 177, 60, 94, 247, 164, 148, 218, 51, 139, 77, 127, 20, 91, 174, 135, 154, 94, 169, 246, 191, 205, 203, 151, 178, 120, 205, 156, 193, 1, 215, 118, 45, 59, 76, 115, 119, 54, 18, 61, 82, 204, 29, 249, 107, 24, 82, 87, 66, 197, 135, 120, 103, 125, 192, 156, 50, 196, 25, 94, 0},
			SignDataHex:    []byte("5bab0a48a630c94a1f8e9073adf5866d362e68539689e58d7320cbdc697c3f8ef5fbe4caffaa2e3edbbfd19d1141100fc50ea9989d1429cad74072b4eb15149577443402a475af6e9a1dfdb672ba601b3e80b56817b6c7da763401e53e3a2e544b58beb76ef6a3ff648ca46df1ec8be6e97b9cac21bf7a1d657c2b2feb6015a5476eaa75b3fd3cd3f906c644b52afeb2deb69af9986c5b7f8c9fdbe99da752c473febe595b967b1046c6d60d58499043d08f6b3c33951101ecc49c8e3a6de7cf961a1d36b13c5ef7a494da338b4d7f145bae879a5ea9f6bfcdcb97b278cd9cc101d7762d3b4c737736123d52cc1df96b18525742c58778677dc09c32c4195e00"),
			SignDataBase64: []byte("W6sKSKYwyUofjpBzrfWGbTYuaFOWieWNcyDL3Gl8P471++TK/6ouPtu/0Z0RQRAPxQ6pmJ0UKcrXQHK06xUUlXdENAKkda9umh39tnK6YBs+gLVoF7bH2nY0AeU+Oi5US1i+t272o/9kjKRt8eyL5ul7nKwhv3odZXwrL+tgFaVHbqp1s/080/kGxkS1Kv6y3raa+ZhsW3+Mn9vpnadSxHP+vllblnsQRsbWDVhJkEPQj2s8M5URAezEnI46befPlhodNrE8XveklNozi01/FFuuh5peqfa/zcuXsnjNnMEB13YtO0xzdzYSPVLMHflrGFJXQsWHeGd9wJwyxBleAA=="),
		},
	}

	random := testRandomReader{}
	for _, testCase := range testCases {
		sum := sha256.Sum256(testCase.Data)
		hashed := sum[:]

		// None
		sign, err := privateKey.SignPKCS1v15(hashed, WithRandom(random))
		if err != nil {
			t.Fatal(err)
		}

		err = publicKey.VerifyPKCS1v15(hashed, sign, WithRandom(random))
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(sign, testCase.SignData) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, sign, testCase.SignData)
		}

		// Hex
		sign, err = privateKey.SignPKCS1v15(hashed, WithRandom(random), WithHex())
		if err != nil {
			t.Fatal(err)
		}

		err = publicKey.VerifyPKCS1v15(hashed, sign, WithRandom(random), WithHex())
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(sign, testCase.SignDataHex) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, sign, testCase.SignDataHex)
		}

		// Base64
		sign, err = privateKey.SignPKCS1v15(hashed, WithRandom(random), WithBase64())
		if err != nil {
			t.Fatal(err)
		}

		err = publicKey.VerifyPKCS1v15(hashed, sign, WithRandom(random), WithBase64())
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(sign, testCase.SignDataBase64) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, sign, testCase.SignDataBase64)
		}
	}
}

// go test -v -cover -run=^TestSignVerifyPSS$
func TestSignVerifyPSS(t *testing.T) {
	privateKey := newTestPrivateKey()
	publicKey := newTestPublicKey()

	testCases := []signTestCase{
		{
			Data:           []byte(""),
			SignData:       []byte{79, 121, 91, 72, 127, 146, 214, 110, 79, 129, 41, 57, 255, 146, 106, 190, 237, 56, 9, 137, 179, 220, 204, 206, 218, 60, 117, 181, 241, 147, 92, 101, 138, 238, 228, 59, 198, 124, 150, 55, 191, 71, 243, 38, 67, 126, 147, 137, 38, 117, 163, 238, 201, 180, 62, 48, 217, 34, 219, 172, 19, 78, 178, 2, 177, 212, 181, 210, 172, 156, 21, 201, 85, 241, 241, 22, 237, 90, 128, 196, 59, 78, 157, 146, 189, 121, 5, 98, 55, 149, 42, 16, 248, 108, 85, 164, 126, 179, 215, 35, 238, 142, 84, 127, 252, 75, 125, 47, 158, 87, 50, 44, 187, 111, 152, 184, 35, 26, 198, 96, 7, 79, 190, 8, 63, 48, 117, 13, 110, 118, 29, 213, 5, 73, 86, 142, 29, 244, 250, 121, 181, 218, 197, 82, 20, 30, 108, 143, 210, 36, 187, 58, 97, 177, 103, 109, 192, 119, 173, 22, 38, 144, 32, 11, 250, 171, 47, 92, 249, 47, 84, 162, 187, 140, 178, 231, 118, 171, 36, 27, 164, 23, 118, 202, 174, 55, 189, 165, 169, 247, 194, 106, 87, 186, 58, 23, 165, 209, 232, 208, 15, 108, 78, 156, 3, 74, 69, 137, 108, 17, 174, 69, 134, 14, 20, 220, 34, 220, 246, 19, 77, 154, 110, 52, 20, 99, 19, 3, 113, 197, 189, 119, 121, 231, 208, 157, 236, 92, 27, 207, 153, 202, 238, 168, 114, 41, 177, 211, 90, 46, 166, 194, 206, 176, 44, 180},
			SignDataHex:    []byte("4f795b487f92d66e4f812939ff926abeed380989b3dcccceda3c75b5f1935c658aeee43bc67c9637bf47f326437e93892675a3eec9b43e30d922dbac134eb202b1d4b5d2ac9c15c955f1f116ed5a80c43b4e9d92bd79056237952a10f86c55a47eb3d723ee8e547ffc4b7d2f9e57322cbb6f98b8231ac660074fbe083f30750d6e761dd50549568e1df4fa79b5dac552141e6c8fd224bb3a61b1676dc077ad162690200bfaab2f5cf92f54a2bb8cb2e776ab241ba41776caae37bda5a9f7c26a57ba3a17a5d1e8d00f6c4e9c034a45896c11ae45860e14dc22dcf6134d9a6e341463130371c5bd7779e7d09dec5c1bcf99caeea87229b1d35a2ea6c2ceb02cb4"),
			SignDataBase64: []byte("T3lbSH+S1m5PgSk5/5Jqvu04CYmz3MzO2jx1tfGTXGWK7uQ7xnyWN79H8yZDfpOJJnWj7sm0PjDZItusE06yArHUtdKsnBXJVfHxFu1agMQ7Tp2SvXkFYjeVKhD4bFWkfrPXI+6OVH/8S30vnlcyLLtvmLgjGsZgB0++CD8wdQ1udh3VBUlWjh30+nm12sVSFB5sj9IkuzphsWdtwHetFiaQIAv6qy9c+S9UoruMsud2qyQbpBd2yq43vaWp98JqV7o6F6XR6NAPbE6cA0pFiWwRrkWGDhTcItz2E02abjQUYxMDccW9d3nn0J3sXBvPmcruqHIpsdNaLqbCzrAstA=="),
		},
		{
			Data:           []byte("123"),
			SignData:       []byte{88, 112, 203, 36, 118, 246, 128, 76, 125, 169, 119, 56, 97, 151, 166, 135, 19, 241, 44, 63, 77, 225, 96, 172, 71, 18, 135, 241, 183, 79, 179, 249, 227, 161, 107, 218, 198, 157, 199, 90, 161, 180, 6, 250, 84, 206, 214, 36, 115, 81, 57, 223, 137, 37, 94, 255, 167, 41, 177, 83, 140, 236, 203, 253, 201, 237, 196, 165, 208, 51, 29, 153, 45, 33, 111, 239, 126, 129, 69, 162, 223, 14, 49, 94, 64, 216, 44, 92, 53, 135, 81, 113, 184, 158, 45, 9, 171, 97, 182, 196, 241, 117, 160, 234, 246, 123, 151, 121, 111, 250, 197, 6, 156, 221, 97, 46, 224, 190, 87, 155, 72, 168, 161, 9, 86, 207, 209, 15, 10, 0, 219, 13, 144, 95, 52, 174, 248, 99, 104, 122, 157, 48, 240, 136, 94, 29, 251, 224, 223, 35, 102, 141, 78, 192, 208, 8, 233, 91, 217, 149, 79, 43, 46, 60, 73, 149, 136, 122, 103, 68, 24, 115, 204, 179, 53, 246, 74, 163, 221, 5, 84, 115, 37, 178, 18, 65, 2, 235, 103, 238, 66, 242, 129, 192, 141, 136, 215, 142, 6, 67, 79, 105, 129, 58, 215, 242, 24, 195, 23, 191, 153, 178, 107, 204, 85, 138, 126, 60, 171, 110, 42, 8, 215, 80, 156, 13, 115, 12, 88, 93, 184, 138, 223, 64, 32, 58, 40, 225, 95, 76, 191, 22, 130, 245, 161, 9, 112, 60, 179, 43, 66, 134, 184, 48, 26, 54},
			SignDataHex:    []byte("5870cb2476f6804c7da977386197a68713f12c3f4de160ac471287f1b74fb3f9e3a16bdac69dc75aa1b406fa54ced624735139df89255effa729b1538ceccbfdc9edc4a5d0331d992d216fef7e8145a2df0e315e40d82c5c35875171b89e2d09ab61b6c4f175a0eaf67b97796ffac5069cdd612ee0be579b48a8a10956cfd10f0a00db0d905f34aef863687a9d30f0885e1dfbe0df23668d4ec0d008e95bd9954f2b2e3c4995887a67441873ccb335f64aa3dd05547325b2124102eb67ee42f281c08d88d78e06434f69813ad7f218c317bf99b26bcc558a7e3cab6e2a08d7509c0d730c585db88adf40203a28e15f4cbf1682f5a109703cb32b4286b8301a36"),
			SignDataBase64: []byte("WHDLJHb2gEx9qXc4YZemhxPxLD9N4WCsRxKH8bdPs/njoWvaxp3HWqG0BvpUztYkc1E534klXv+nKbFTjOzL/cntxKXQMx2ZLSFv736BRaLfDjFeQNgsXDWHUXG4ni0Jq2G2xPF1oOr2e5d5b/rFBpzdYS7gvlebSKihCVbP0Q8KANsNkF80rvhjaHqdMPCIXh374N8jZo1OwNAI6VvZlU8rLjxJlYh6Z0QYc8yzNfZKo90FVHMlshJBAutn7kLygcCNiNeOBkNPaYE61/IYwxe/mbJrzFWKfjyrbioI11CcDXMMWF24it9AIDoo4V9MvxaC9aEJcDyzK0KGuDAaNg=="),
		},
		{
			Data:           []byte("你好，世界"),
			SignData:       []byte{64, 251, 172, 211, 8, 193, 4, 92, 254, 189, 174, 31, 67, 26, 73, 152, 128, 228, 13, 238, 43, 46, 136, 72, 230, 125, 128, 82, 101, 194, 164, 224, 230, 144, 156, 162, 107, 40, 129, 225, 137, 8, 145, 108, 237, 71, 169, 186, 183, 124, 37, 218, 244, 130, 224, 172, 191, 226, 227, 184, 74, 103, 231, 247, 44, 18, 243, 222, 132, 116, 125, 243, 243, 237, 122, 19, 249, 208, 26, 79, 92, 202, 47, 99, 84, 157, 109, 88, 56, 184, 53, 182, 159, 227, 40, 12, 244, 142, 183, 65, 115, 119, 254, 139, 14, 232, 32, 115, 124, 27, 31, 78, 90, 20, 212, 120, 233, 78, 174, 202, 180, 67, 96, 124, 32, 165, 54, 133, 172, 43, 114, 135, 211, 7, 27, 149, 194, 209, 83, 49, 194, 134, 255, 69, 54, 59, 183, 142, 54, 48, 232, 223, 78, 13, 247, 111, 147, 196, 109, 246, 191, 106, 197, 114, 70, 39, 144, 215, 147, 223, 20, 196, 170, 155, 20, 90, 219, 160, 48, 183, 31, 9, 92, 100, 18, 79, 225, 248, 226, 232, 32, 64, 55, 20, 16, 156, 23, 180, 59, 177, 29, 102, 181, 101, 231, 64, 138, 51, 206, 66, 176, 11, 247, 64, 145, 209, 154, 241, 109, 120, 12, 146, 99, 251, 173, 251, 37, 222, 11, 80, 46, 188, 40, 15, 241, 114, 203, 94, 0, 151, 65, 157, 51, 100, 128, 114, 50, 20, 252, 22, 122, 240, 91, 25, 188, 40},
			SignDataHex:    []byte("40fbacd308c1045cfebdae1f431a499880e40dee2b2e8848e67d805265c2a4e0e6909ca26b2881e18908916ced47a9bab77c25daf482e0acbfe2e3b84a67e7f72c12f3de84747df3f3ed7a13f9d01a4f5cca2f63549d6d5838b835b69fe3280cf48eb7417377fe8b0ee820737c1b1f4e5a14d478e94eaecab443607c20a53685ac2b7287d3071b95c2d15331c286ff45363bb78e3630e8df4e0df76f93c46df6bf6ac572462790d793df14c4aa9b145adba030b71f095c64124fe1f8e2e820403714109c17b43bb11d66b565e7408a33ce42b00bf74091d19af16d780c9263fbadfb25de0b502ebc280ff172cb5e0097419d336480723214fc167af05b19bc28"),
			SignDataBase64: []byte("QPus0wjBBFz+va4fQxpJmIDkDe4rLohI5n2AUmXCpODmkJyiayiB4YkIkWztR6m6t3wl2vSC4Ky/4uO4Smfn9ywS896EdH3z8+16E/nQGk9cyi9jVJ1tWDi4Nbaf4ygM9I63QXN3/osO6CBzfBsfTloU1HjpTq7KtENgfCClNoWsK3KH0wcblcLRUzHChv9FNju3jjYw6N9ODfdvk8Rt9r9qxXJGJ5DXk98UxKqbFFrboDC3HwlcZBJP4fji6CBANxQQnBe0O7EdZrVl50CKM85CsAv3QJHRmvFteAySY/ut+yXeC1AuvCgP8XLLXgCXQZ0zZIByMhT8FnrwWxm8KA=="),
		},
	}

	random := testRandomReader{}
	for _, testCase := range testCases {
		sum := sha256.Sum256(testCase.Data)
		digest := sum[:]

		// None
		sign, err := privateKey.SignPSS(digest, WithRandom(random))
		if err != nil {
			t.Fatal(err)
		}

		err = publicKey.VerifyPSS(digest, sign, WithRandom(random))
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(sign, testCase.SignData) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, sign, testCase.SignData)
		}

		// Hex
		sign, err = privateKey.SignPSS(digest, WithRandom(random), WithHex())
		if err != nil {
			t.Fatal(err)
		}

		err = publicKey.VerifyPSS(digest, sign, WithRandom(random), WithHex())
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(sign, testCase.SignDataHex) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, sign, testCase.SignDataHex)
		}

		// Base64
		sign, err = privateKey.SignPSS(digest, WithRandom(random), WithBase64())
		if err != nil {
			t.Fatal(err)
		}

		err = publicKey.VerifyPSS(digest, sign, WithRandom(random), WithBase64())
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(sign, testCase.SignDataBase64) {
			t.Fatalf("data %q: got %+v != expect %+v", testCase.Data, sign, testCase.SignDataBase64)
		}
	}
}
