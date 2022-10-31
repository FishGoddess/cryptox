# 🔒 Cryptox

[![Go Doc](_icons/godoc.svg)](https://pkg.go.dev/github.com/FishGoddess/cryptox)
[![License](_icons/license.svg)](https://opensource.org/licenses/MIT)
[![License](_icons/coverage.svg)](_icons/coverage.svg)
![Test](https://github.com/FishGoddess/cryptox/actions/workflows/test.yml/badge.svg)

**Cryptox** is a kit for safety which includes some common encrypted/decrypted algorithms.

[阅读中文版的文档](./README.md)

### 💡 Features

* DES/3DES/AES Supports.
* RSA/ECC Supports.
* ECB/CBC/OFB/CFB/CTR Supports.
* PKCS5/PKCS7/ZERO/NO Supports.
* MD5/SHA1/SHA256/SHA512/HMAC Supports.
* CRC/FNV Supports.
* HEX/BASE64 Supports.

_Check [HISTORY.md](./HISTORY.md) and [FUTURE.md](./FUTURE.md) to know about more information._

### ⚙ How to use

```shell
$ go get -u github.com/FishGoddess/cryptox
```

* [des](_examples/des.go)
* [triple_des](_examples/triple_des.go)
* [aes](_examples/aes.go)
* [hash](_examples/hash.go)

### 🚴🏻 Benchmarks

```shell
$ go test -v -bench=. -benchtime=1s _examples/*_test.go
```

_Note: Data size is 128 bytes, ecb/cbc uses pkcs7 padding, cfb/ofb/ctr is no padding._

```
goos: darwin
goarch: amd64
cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz

BenchmarkAESEncryptWithECB-12            2376924               506 ns/op             960 B/op          6 allocs/op
BenchmarkAESEncryptWithCBC-12            1704799               699 ns/op            1072 B/op          9 allocs/op
BenchmarkAESEncryptWithCFB-12            1890339               632 ns/op             816 B/op          8 allocs/op
BenchmarkAESEncryptWithOFB-12            1000000              1029 ns/op            1312 B/op          8 allocs/op
BenchmarkAESEncryptWithCTR-12             979789              1186 ns/op            1312 B/op          8 allocs/op
BenchmarkAESDecryptWithECB-12            2811610               429 ns/op             720 B/op          5 allocs/op
BenchmarkAESDecryptWithCBC-12            2013831               613 ns/op             832 B/op          8 allocs/op
BenchmarkAESDecryptWithCFB-12            1935090               625 ns/op             816 B/op          8 allocs/op
BenchmarkAESDecryptWithOFB-12            1000000              1025 ns/op            1312 B/op          8 allocs/op
BenchmarkAESDecryptWithCTR-12            1000000              1173 ns/op            1312 B/op          8 allocs/op
BenchmarkDESEncryptWithECB-12             351558              3444 ns/op             512 B/op          3 allocs/op
BenchmarkDESEncryptWithCBC-12             334164              3668 ns/op             608 B/op          6 allocs/op
BenchmarkDESEncryptWithCFB-12             352360              3566 ns/op             352 B/op          5 allocs/op
BenchmarkDESEncryptWithOFB-12             148867              8146 ns/op             856 B/op          5 allocs/op
BenchmarkDESEncryptWithCTR-12             138829              8547 ns/op             856 B/op          5 allocs/op
BenchmarkDESDecryptWithECB-12             356511              3427 ns/op             272 B/op          2 allocs/op
BenchmarkDESDecryptWithCBC-12             327507              3664 ns/op             368 B/op          5 allocs/op
BenchmarkDESDecryptWithCFB-12             345454              3552 ns/op             352 B/op          5 allocs/op
BenchmarkDESDecryptWithOFB-12             145267              8183 ns/op             856 B/op          5 allocs/op
BenchmarkDESDecryptWithCTR-12             144640              8451 ns/op             856 B/op          5 allocs/op
BenchmarkTripleDESEncryptWithECB-12       131902              9259 ns/op             768 B/op          3 allocs/op
BenchmarkTripleDESEncryptWithCBC-12       126849              9468 ns/op             864 B/op          6 allocs/op
BenchmarkTripleDESEncryptWithCFB-12       130987              9276 ns/op             608 B/op          5 allocs/op
BenchmarkTripleDESEncryptWithOFB-12        57150             20805 ns/op            1112 B/op          5 allocs/op
BenchmarkTripleDESEncryptWithCTR-12        55443             21344 ns/op            1112 B/op          5 allocs/op
BenchmarkTripleDESDecryptWithECB-12       132991              9236 ns/op             528 B/op          2 allocs/op
BenchmarkTripleDESDecryptWithCBC-12       117877              9483 ns/op             624 B/op          5 allocs/op
BenchmarkTripleDESDecryptWithCFB-12       129415              9064 ns/op             608 B/op          5 allocs/op
BenchmarkTripleDESDecryptWithOFB-12        56397             20979 ns/op            1112 B/op          5 allocs/op
BenchmarkTripleDESDecryptWithCTR-12        56103             21694 ns/op            1112 B/op          5 allocs/op

BenchmarkMD5-12                  7447408               156.3 ns/op           112 B/op          2 allocs/op
BenchmarkSHA1-12                 6629499               184.2 ns/op           136 B/op          2 allocs/op
BenchmarkSHA224-12               4768708               249.6 ns/op           160 B/op          2 allocs/op
BenchmarkSHA256-12               4755806               256.2 ns/op           160 B/op          2 allocs/op
BenchmarkSHA384-12               3717706               329.8 ns/op           272 B/op          2 allocs/op
BenchmarkSHA512-12               3679125               325.5 ns/op           288 B/op          2 allocs/op
BenchmarkHMAC-12                 1215033               988.4 ns/op           512 B/op          6 allocs/op
BenchmarkCRC32IEEE-12           17037747                70.4 ns/op            24 B/op          2 allocs/op
BenchmarkCRC64ISO-12            26904604                44.8 ns/op             8 B/op          1 allocs/op
BenchmarkCRC64ECMA-12           26632101                44.4 ns/op             8 B/op          1 allocs/op
BenchmarkFnv32-12               41738200                28.2 ns/op             8 B/op          1 allocs/op
BenchmarkFnv32a-12              42062208                29.0 ns/op             8 B/op          1 allocs/op
BenchmarkFnv64-12               39065052                29.9 ns/op             8 B/op          1 allocs/op
BenchmarkFnv64a-12              39740802                29.9 ns/op             8 B/op          1 allocs/op
BenchmarkFnv128-12              23474830                50.2 ns/op            16 B/op          1 allocs/op
BenchmarkFnv128a-12             24201123                50.3 ns/op            16 B/op          1 allocs/op
```

### 🎨 Contributing

If you find that something is not working as expected please open an _**issue**_.

### 💪 Projects using cryptox

| Project | Author | Description | link                   |
|---------|--------|-------------|------------------------|
|         |        |             | [Github]() / [Gitee]() |

At last, I want to thank JetBrains for **free JetBrains Open Source license(s)**, because cryptox is developed with Idea
/ GoLand under it.

<a href="https://www.jetbrains.com/?from=cryptox" target="_blank"><img src="./_icons/jetbrains.png" width="250"/></a>