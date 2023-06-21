// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/FishGoddess/cryptox"
)

func newTestPrivateKey(t *testing.T) PrivateKey {
	keyBytes := []byte(`-----BEGIN PRIVATE KEY-----
MIIEowIBAAKCAQEAu0KvOo1/9owLI+GZuzluPmixfDEeNBA+t2qppsVT9xb4huZb
wXwowNP6KU4vPpdF0KhHSmaFOf8IIXSoZ/xI7bLxs10Te1fSqZInVuj912VLj/uw
uK7OG1zfsN0mt8I2d+9zYzAGykh/U/skYALOzvmfvamcQGHT1TuxOsQln3Eq0477
VGmk53vTMOxEU033CUEabuNOiWlM8TsaDEqxYWO3Two+rSNW4S48WTQhekhqtxxg
0LhJfB/T9tCOmzuTln4oVk4peZW+CH0UJijtd/2Ypx/Hyk0yXQgGtIKUN35avn2/
ga56HOxGYumk22Q4Xv4OZOmevzPLyvRZDZMWuwIDAQABAoIBACxasCybRXr9Usot
7n7VLJKls5xp+fB1BJXnMsXoqWm2TCmPuJ4MrY525yMPfMtDg2rX4QLzY40IJkHe
YuE2dYOvxeYpHqsxcxltH9pLF40EVjCFeidUaEc86VL4HuqZmtMvqVIOFx2krFwU
+VmwcJG/uKFw4iyxvz4bhHAZ85tfB+zvB5ZwwBNQ1hhcUlbdzIFQxe0p+IIoxVTy
bHGRX5Pvm95PbgLAJUYXans7xzmN+czIQ4+7REBXoO6OmnnhoWvkfOx4oaflnq5H
BlesQbbPNXVzFBQA6JzokavkfkgiMJh5582P9AmA+hEzeA+0o5aN5UcK8LzceFc/
CTE+pRECgYEA0shkcL0EMibMkKzwpJ5eZzIOtcraBHA7AJgG5m8LJhmAZGQSAHdx
Ycp/pXJbkKzEt1QoH+YHxP8YsaCHtcNvggVwKHJgDqDh2RVVGGWDI4E+kswd/8nc
EO4Ki+znURn95mSFTQZt6ukUS8RVo9fEmGPG730KspAHIvmgiXct7HMCgYEA426D
PcxpULZ6TF/TiZ8QyVQiD/lAGLyXkqgz9tvvn4LPQbwg48ACEs17Cyg/YjEe6hOt
e3Ia+LHvYbHnQ+6JkbstBf4xMNqpIdrvTs87m/ev/prUPTTitwhLKYjBCquitk6d
sGIn6TTZdC0wbEodI1nFP6SIIXBpejNQic6AopkCgYBmgGjHokNuGAwWtuL3SsRh
rqgUo6bNzb4DleqVGJ71UiVrrHZMn8kVYyIb1LbObhXjiRtSF8zjcaISjxwvufB5
7CcUpDouIvJxXLxa9tKE648AWB6miwVnfjrGvNfoSpl79poUUPIW8G2cQsfau0yx
RqQxRj9zgjLWQUpeTwSYHQKBgCM+gQAWqUtku9cSEooFKGjKrOykx5YNw79qaYMb
2ipx7wRUzxP8MVYQmbzE4+2nhw7nNb8nk55ulJYjJ5+TW6ZFx1hiZ+UWPZeNggBI
hQhKfe+KttE1XNzYYC1zj9bDeleeHzmyPFUbZ4dlaVeetJ1B0Btot9/Wt8HEKfrx
EWYhAoGBAMkxeAD1q9LA6lgpNzflna0bWgKLpHj0Iz6/9wMmVkxTMJzQDxMbNhUj
Fx6f6eSBQiEJPPypIKoMRctcBX+tmR4iuLhe5y8S9uVW7DUP3I4mGeGkap/Fz4fO
jqy/B5Twb/tggfdM5id+3frrF2xf7/bgPwNij9zLKovJgEIALil4
-----END PRIVATE KEY-----`)

	privateKey, err := ParsePrivateKey(keyBytes)
	if err != nil {
		t.Error(err)
	}

	return privateKey
}

// go test -v -cover -run=^TestPrivateKey$
func TestPrivateKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}

	privateKeyBytes, err := X509.PKCS1PrivateKeyEncoder(privateKey)
	if err != nil {
		t.Error(err)
	}

	key := newPrivateKey(privateKey, privateKeyBytes)
	if key.key != privateKey {
		t.Errorf("key.key %+v != privateKey %+v", key.key, privateKey)
	}

	if key.keyBytes.String() != privateKeyBytes.String() {
		t.Errorf("key.keyBytes %+v != privateKeyBytes %+v", key.keyBytes, privateKeyBytes)
	}

	if key.Key() != privateKey {
		t.Errorf("key.Key() %+v != privateKey %+v", key.Key(), privateKey)
	}

	if key.Bytes().String() != privateKeyBytes.String() {
		t.Errorf("key.Bytes() %+v != privateKeyBytes %+v", key.Bytes(), privateKeyBytes)
	}

	expectPrivateKey := PrivateKey{
		key:      privateKey,
		keyBytes: privateKeyBytes,
	}

	if !key.EqualsTo(expectPrivateKey) {
		t.Errorf("key %+v != expectPrivateKey %+v", key, expectPrivateKey)
	}

	if key.String() != privateKeyBytes.String() {
		t.Errorf("key.String() %+v != privateKeyBytes %+v", key.String(), privateKeyBytes)
	}
}

// go test -v -cover -run=^TestPrivateKeySignPKCS1v15$
func TestPrivateKeySignPKCS1v15(t *testing.T) {
	publicKey := newTestPublicKey(t)
	privateKey := newTestPrivateKey(t)

	cases := []string{
		"d41d8cd98f00b204e9800998ecf8427e", "202cb962ac59075b964b07152d234b70", "dbefd3ada018615b35588a01e216ae6e",
	}

	for _, msg := range cases {
		signature, err := privateKey.SignPKCS1v15(cryptox.Bytes(msg))
		if err != nil {
			t.Error(err)
		}

		err = publicKey.VerifyPKCS1v15(cryptox.Bytes(msg), signature)
		if err != nil {
			t.Error(err)
		}
	}
}

// go test -v -cover -run=^TestPrivateKeySignPSS$
func TestPrivateKeySignPSS(t *testing.T) {
	publicKey := newTestPublicKey(t)
	privateKey := newTestPrivateKey(t)

	cases := []string{
		"d41d8cd98f00b204e9800998ecf8427e", "202cb962ac59075b964b07152d234b70", "dbefd3ada018615b35588a01e216ae6e",
	}

	for _, msg := range cases {
		signature, err := privateKey.SignPSS(cryptox.Bytes(msg), 0)
		if err != nil {
			t.Error(err)
		}

		err = publicKey.VerifyPSS(cryptox.Bytes(msg), signature, 0)
		if err != nil {
			t.Error(err)
		}
	}
}
