# 🔒 Cryptox

[![Go Doc](_icons/godoc.svg)](https://pkg.go.dev/github.com/FishGoddess/cryptox)
[![License](_icons/license.svg)](https://opensource.org/licenses/MIT)
[![Coverage](_icons/coverage.svg)](_icons/coverage.svg)
![Test](https://github.com/FishGoddess/cryptox/actions/workflows/test.yml/badge.svg)

**Cryptox** is a kit for safety which includes some common encrypt/decrypt algorithms.

[阅读中文版的文档](./README.md)

### 💡 Features

* HEX/BASE64 encoding supports.
* MD5/SHA1/SHA256/SHA384/SHA512 hash supports.
* CRC/FNV hash supports.
* HMAC mixed hash supports.
* DES/3DES/AES encrypt and decrypt supports.
* RSA/ECC encrypt and decrypt supports.
* ECB/CBC/OFB/CFB/CTR/GCM mode supports.
* ZERO/PKCS5/PKCS7 padding supports.

_Check [HISTORY.md](./HISTORY.md) and [FUTURE.md](./FUTURE.md) to know about more information._

### ⚙ How to use

```shell
$ go get -u github.com/FishGoddess/cryptox
```

* [hash](_examples/hash.go)
* [hmac](_examples/hmac.go)
* [des](_examples/des.go)
* [triple_des](_examples/triple_des.go)
* [aes](_examples/aes.go)
* [rsa](_examples/rsa.go)
* [rsa_key](_examples/rsa_key.go)

### 🚴🏻 Benchmarks

```shell
$ make bench
```

_Note: Data size is 128 bytes, ecb/cbc uses pkcs7 padding, cfb/ofb/ctr/gcm is no padding._

```
goos: linux
goarch: amd64
cpu: AMD EPYC 7K62 48-Core Processor

BenchmarkGenerateBytes-2        11454386               102.6 ns/op            16 B/op          1 allocs/op
BenchmarkGenerateString-2       11392647               106.1 ns/op            16 B/op          1 allocs/op

BenchmarkMD5-2           8933902               133.6 ns/op             0 B/op          0 allocs/op
BenchmarkSHA1-2          7997222               148.7 ns/op             0 B/op          0 allocs/op
BenchmarkSHA224-2       12905275                93.82 ns/op            0 B/op          0 allocs/op
BenchmarkSHA256-2       13305572                90.11 ns/op            0 B/op          0 allocs/op
BenchmarkSHA384-2        4501677               266.8 ns/op             0 B/op          0 allocs/op
BenchmarkSHA512-2        4457496               272.0 ns/op             0 B/op          0 allocs/op
BenchmarkCRC32IEEE-2    37977817                26.99 ns/op            0 B/op          0 allocs/op
BenchmarkCRC64ISO-2     49464211                23.77 ns/op            0 B/op          0 allocs/op
BenchmarkCRC64ECMA-2    47987559                23.85 ns/op            0 B/op          0 allocs/op
BenchmarkFnv32-2        88136509                13.91 ns/op            0 B/op          0 allocs/op
BenchmarkFnv32a-2       92693382                13.53 ns/op            0 B/op          0 allocs/op
BenchmarkFnv64-2        78227923                15.31 ns/op            0 B/op          0 allocs/op
BenchmarkFnv64a-2       79213070                15.35 ns/op            0 B/op          0 allocs/op
BenchmarkFnv128-2       15003325                77.31 ns/op           16 B/op          1 allocs/op
BenchmarkFnv128a-2      15473437                76.73 ns/op           16 B/op          1 allocs/op

BenchmarkHMACUsingMD5-2          1418788               837.4 ns/op           432 B/op          6 allocs/op
BenchmarkHMACUsingSHA1-2         1304995               922.9 ns/op           472 B/op          6 allocs/op
BenchmarkHMACUsingSHA224-2       1879555               651.9 ns/op           512 B/op          6 allocs/op
BenchmarkHMACUsingSHA256-2       1880856               656.8 ns/op           512 B/op          6 allocs/op
BenchmarkHMACUsingSHA384-2        702820              1679 ns/op             848 B/op          6 allocs/op
BenchmarkHMACUsingSHA512-2        691454              1629 ns/op             864 B/op          6 allocs/op

BenchmarkDESEncryptECB-2          321910              3601 ns/op             656 B/op          4 allocs/op
BenchmarkDESEncryptCBC-2          307196              3911 ns/op             752 B/op          7 allocs/op
BenchmarkDESEncryptCFB-2          319731              3689 ns/op             480 B/op          6 allocs/op
BenchmarkDESEncryptOFB-2          126572              9045 ns/op             984 B/op          6 allocs/op
BenchmarkDESEncryptCTR-2          125204              9471 ns/op             984 B/op          6 allocs/op
BenchmarkDESDecryptECB-2          340486              3461 ns/op             272 B/op          2 allocs/op
BenchmarkDESDecryptCBC-2          321182              3730 ns/op             368 B/op          5 allocs/op
BenchmarkDESDecryptCFB-2          329288              3607 ns/op             352 B/op          5 allocs/op
BenchmarkDESDecryptOFB-2          131550              9054 ns/op             856 B/op          5 allocs/op
BenchmarkDESDecryptCTR-2          125089              9539 ns/op             856 B/op          5 allocs/op

BenchmarkDESEncryptECBTriple-2            124927              9474 ns/op             912 B/op          4 allocs/op
BenchmarkDESEncryptCBCTriple-2            121834              9701 ns/op            1008 B/op          7 allocs/op
BenchmarkDESEncryptCFBTriple-2            127020              9334 ns/op             736 B/op          6 allocs/op
BenchmarkDESEncryptOFBTriple-2             50922             23598 ns/op            1240 B/op          6 allocs/op
BenchmarkDESEncryptCTRTriple-2             49735             23873 ns/op            1240 B/op          6 allocs/op
BenchmarkDESDecryptECBTriple-2            128005              9328 ns/op             528 B/op          2 allocs/op
BenchmarkDESDecryptCBCTriple-2            122860              9558 ns/op             624 B/op          5 allocs/op
BenchmarkDESDecryptCFBTriple-2            126201              9334 ns/op             608 B/op          5 allocs/op
BenchmarkDESDecryptOFBTriple-2             50688             23291 ns/op            1112 B/op          5 allocs/op
BenchmarkDESDecryptCTRTriple-2             50391             23913 ns/op            1112 B/op          5 allocs/op

BenchmarkAESEncryptECB-2         1960758               578.4 ns/op          1104 B/op          7 allocs/op
BenchmarkAESEncryptCBC-2         1413351               842.1 ns/op          1216 B/op         10 allocs/op
BenchmarkAESEncryptCFB-2         1657416               726.3 ns/op           944 B/op          9 allocs/op
BenchmarkAESEncryptOFB-2          924843              1206 ns/op            1440 B/op          9 allocs/op
BenchmarkAESEncryptCTR-2          808509              1381 ns/op            1440 B/op          9 allocs/op
BenchmarkAESEncryptGCM-2         1784593               661.2 ns/op          1168 B/op          7 allocs/op
BenchmarkAESDecryptECB-2         2590693               475.5 ns/op           720 B/op          5 allocs/op
BenchmarkAESDecryptCBC-2         1715998               711.6 ns/op           832 B/op          8 allocs/op
BenchmarkAESDecryptCFB-2         1809044               656.0 ns/op           816 B/op          8 allocs/op
BenchmarkAESDecryptOFB-2          956439              1152 ns/op            1312 B/op          8 allocs/op
BenchmarkAESDecryptCTR-2          841315              1348 ns/op            1312 B/op          8 allocs/op
BenchmarkAESDecryptGCM-2         1944147               633.5 ns/op          1040 B/op          6 allocs/op

BenchmarkRSAEncryptPKCS1v15-2                       1252            948252 ns/op           95488 B/op        155 allocs/op
BenchmarkRSAEncryptOAEP-2                           1315            909433 ns/op           95592 B/op        160 allocs/op
BenchmarkRSADecryptPKCS1v15-2                        166           7219740 ns/op            7600 B/op         16 allocs/op
BenchmarkRSADecryptPKCS1v15SessionKey-2              165           7154349 ns/op            7600 B/op         16 allocs/op
BenchmarkRSADecryptOAEP-2                            166           7150228 ns/op            7704 B/op         21 allocs/op
BenchmarkRSASignPSS-2                                154           7670215 ns/op           67168 B/op        100 allocs/op
BenchmarkRSASignPKCS1v15-2                           156           7637694 ns/op           66992 B/op         95 allocs/op
BenchmarkRSAVerifyPSS-2                             1308            901882 ns/op           95184 B/op        159 allocs/op
BenchmarkRSAVerifyPKCS1v15-2                        1339            895115 ns/op           94976 B/op        154 allocs/op

BenchmarkRSAGenerateKey1024PKCS1PKIX-2                93          20882099 ns/op         1048351 B/op       4090 allocs/op
BenchmarkRSAGenerateKey2048PKCS1PKIX-2                12         179918684 ns/op         3038840 B/op       8000 allocs/op
BenchmarkRSAGenerateKey4096PKCS1PKIX-2                 1        3257891003 ns/op        15509888 B/op      25112 allocs/op
BenchmarkRSAGenerateKey1024PKCS8PKIX-2                51          22485111 ns/op         1148367 B/op       4450 allocs/op
BenchmarkRSAGenerateKey2048PKCS8PKIX-2                10         149631216 ns/op         2446195 B/op       6550 allocs/op
BenchmarkRSAGenerateKey4096PKCS8PKIX-2                 1        1617318757 ns/op         7521280 B/op      12421 allocs/op
BenchmarkRSAGenerateKey1024PKCS1PKCS1-2               57          22467728 ns/op         1144077 B/op       4387 allocs/op
BenchmarkRSAGenerateKey2048PKCS1PKCS1-2               25         176744406 ns/op         2982597 B/op       7835 allocs/op
BenchmarkRSAGenerateKey4096PKCS1PKCS1-2                1        1577239084 ns/op         7272704 B/op      11896 allocs/op
BenchmarkRSAGenerateKey1024PKCS8PKCS1-2               61          20029226 ns/op         1000116 B/op       3942 allocs/op
BenchmarkRSAGenerateKey2048PKCS8PKCS1-2               21         178710269 ns/op         2998867 B/op       7896 allocs/op
BenchmarkRSAGenerateKey4096PKCS8PKCS1-2                1        2782582400 ns/op        13284080 B/op      21606 allocs/op
```

### 🎨 Contributing

If you find that something is not working as expected please open an _**issue**_.
