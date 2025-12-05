// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

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

// go test -v -cover -run=^TestSignVerifyPKCS1v15$
func TestSignVerifyPKCS1v15(t *testing.T) {
	privateKey := newTestPrivateKey()
	publicKey := newTestPublicKey()

	type testCase struct {
		Data           []byte
		SignData       []byte
		SignDataHex    []byte
		SignDataBase64 []byte
	}

	testCases := []testCase{
		{
			Data:           []byte(""),
			SignData:       []byte(""),
			SignDataHex:    []byte(""),
			SignDataBase64: []byte(""),
		},
		{
			Data:           []byte("123"),
			SignData:       []byte(""),
			SignDataHex:    []byte(""),
			SignDataBase64: []byte(""),
		},
		{
			Data:           []byte("你好，世界"),
			SignData:       []byte(""),
			SignDataHex:    []byte(""),
			SignDataBase64: []byte(""),
		},
	}

	for _, testCase := range testCases {
		sum := sha256.Sum256(testCase.Data)
		hashed := sum[:]

		// None
		sign, err := privateKey.SignPKCS1v15(hashed)
		if err != nil {
			t.Fatal(err)
		}

		err = publicKey.VerifyPKCS1v15(hashed, sign)
		if err != nil {
			t.Fatal(err)
		}

		// Hex
		sign, err = privateKey.SignPKCS1v15(hashed, WithHex())
		if err != nil {
			t.Fatal(err)
		}

		err = publicKey.VerifyPKCS1v15(hashed, sign, WithHex())
		if err != nil {
			t.Fatal(err)
		}

		// Base64
		sign, err = privateKey.SignPKCS1v15(hashed, WithBase64())
		if err != nil {
			t.Fatal(err)
		}

		err = publicKey.VerifyPKCS1v15(hashed, sign, WithBase64())
		if err != nil {
			t.Fatal(err)
		}
	}
}

// go test -v -cover -run=^TestSignVerifyPSS$
func TestSignVerifyPSS(t *testing.T) {
	privateKey := newTestPrivateKey()
	publicKey := newTestPublicKey()

	type testCase struct {
		Data           []byte
		SignData       []byte
		SignDataHex    []byte
		SignDataBase64 []byte
	}

	testCases := []testCase{
		{
			Data:           []byte(""),
			SignData:       []byte(""),
			SignDataHex:    []byte(""),
			SignDataBase64: []byte(""),
		},
		{
			Data:           []byte("123"),
			SignData:       []byte(""),
			SignDataHex:    []byte(""),
			SignDataBase64: []byte(""),
		},
		{
			Data:           []byte("你好，世界"),
			SignData:       []byte(""),
			SignDataHex:    []byte(""),
			SignDataBase64: []byte(""),
		},
	}

	for _, testCase := range testCases {
		sum := sha256.Sum256(testCase.Data)
		digest := sum[:]

		// None
		sign, err := privateKey.SignPSS(digest)
		if err != nil {
			t.Fatal(err)
		}

		err = publicKey.VerifyPSS(digest, sign)
		if err != nil {
			t.Fatal(err)
		}

		// Hex
		sign, err = privateKey.SignPSS(digest, WithHex())
		if err != nil {
			t.Fatal(err)
		}

		err = publicKey.VerifyPSS(digest, sign, WithHex())
		if err != nil {
			t.Fatal(err)
		}

		// Base64
		sign, err = privateKey.SignPSS(digest, WithBase64())
		if err != nil {
			t.Fatal(err)
		}

		err = publicKey.VerifyPSS(digest, sign, WithBase64())
		if err != nil {
			t.Fatal(err)
		}
	}
}
