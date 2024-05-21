# 🔒 Cryptox

[![Go Doc](_icons/godoc.svg)](https://pkg.go.dev/github.com/FishGoddess/cryptox)
[![License](_icons/license.svg)](https://opensource.org/licenses/MIT)
[![Coverage](_icons/coverage.svg)](_icons/coverage.svg)
![Test](https://github.com/FishGoddess/cryptox/actions/workflows/test.yml/badge.svg)

**Cryptox** is a kit for safety which includes some common encrypted/decrypted algorithms.

[阅读中文版的文档](./README.md)

### 💡 Features

* HEX/BASE64 encoding supports.
* MD5/SHA1/SHA256/SHA384/SHA512 hash supports.
* CRC/FNV hash supports.
* HMAC mixed hash supports.
* DES/3DES/AES encrypt and decrypt supports.
* RSA/ECC encrypt and decrypt supports.
* ECB/CBC/OFB/CFB/CTR/GCM mode supports.
* NONE/ZERO/PKCS5/PKCS7 padding supports.

_Check [HISTORY.md](./HISTORY.md) and [FUTURE.md](./FUTURE.md) to know about more information._

### ⚙ How to use

```shell
$ go get -u github.com/FishGoddess/cryptox
```

* [rand](_examples/rand.go)
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

_Note: Data size is 128 bytes, ecb/cbc uses pkcs7 padding, cfb/ofb/ctr is no padding._

```
goos: linux
goarch: amd64
cpu: AMD EPYC 7K62 48-Core Processor

BenchmarkGenerateBytes-2        11821476               108.6 ns/op            16 B/op          1 allocs/op
BenchmarkGenerateString-2       11478427               103.9 ns/op            16 B/op          1 allocs/op

BenchmarkMD5-2           9053053               132.8 ns/op             0 B/op          0 allocs/op
BenchmarkSHA1-2          8112518               147.4 ns/op             0 B/op          0 allocs/op
BenchmarkSHA224-2       12829286                92.96 ns/op            0 B/op          0 allocs/op
BenchmarkSHA256-2       13417588                89.55 ns/op            0 B/op          0 allocs/op
BenchmarkSHA384-2        4516759               270.5 ns/op             0 B/op          0 allocs/op
BenchmarkSHA512-2        4455518               269.5 ns/op             0 B/op          0 allocs/op
BenchmarkCRC32IEEE-2    41162420                26.87 ns/op            0 B/op          0 allocs/op
BenchmarkCRC64ISO-2     49913554                23.53 ns/op            0 B/op          0 allocs/op
BenchmarkCRC64ECMA-2    50856726                23.60 ns/op            0 B/op          0 allocs/op
BenchmarkFnv32-2        91499846                13.48 ns/op            0 B/op          0 allocs/op
BenchmarkFnv32a-2       90893322                13.24 ns/op            0 B/op          0 allocs/op
BenchmarkFnv64-2        75489824                15.47 ns/op            0 B/op          0 allocs/op
BenchmarkFnv64a-2       79207888                15.17 ns/op            0 B/op          0 allocs/op
BenchmarkFnv128-2       15376939                78.16 ns/op           16 B/op          1 allocs/op
BenchmarkFnv128a-2      15460472                77.31 ns/op           16 B/op          1 allocs/op

BenchmarkHMACUsingMD5-2          1426983               843.9 ns/op           432 B/op          6 allocs/op
BenchmarkHMACUsingSHA1-2         1291261               947.7 ns/op           472 B/op          6 allocs/op
BenchmarkHMACUsingSHA224-2       1866373               681.0 ns/op           512 B/op          6 allocs/op
BenchmarkHMACUsingSHA256-2       1835014               655.6 ns/op           512 B/op          6 allocs/op
BenchmarkHMACUsingSHA384-2        711046              1577 ns/op             848 B/op          6 allocs/op
BenchmarkHMACUsingSHA512-2        718261              1573 ns/op             864 B/op          6 allocs/op

BenchmarkDESEncryptECB-2          333966              3502 ns/op             656 B/op          4 allocs/op
BenchmarkDESEncryptCBC-2          314470              3763 ns/op             752 B/op          7 allocs/op
BenchmarkDESEncryptCFB-2          321884              3554 ns/op             480 B/op          6 allocs/op
BenchmarkDESEncryptOFB-2          131870              9316 ns/op             984 B/op          6 allocs/op
BenchmarkDESEncryptCTR-2          126942              9361 ns/op             984 B/op          6 allocs/op
BenchmarkDESDecryptECB-2          343147              3420 ns/op             416 B/op          3 allocs/op
BenchmarkDESDecryptCBC-2          314691              3708 ns/op             512 B/op          6 allocs/op
BenchmarkDESDecryptCFB-2          330295              3562 ns/op             480 B/op          6 allocs/op
BenchmarkDESDecryptOFB-2          133161              8999 ns/op             984 B/op          6 allocs/op
BenchmarkDESDecryptCTR-2          127700              9355 ns/op             984 B/op          6 allocs/op

BenchmarkDESEncryptECBTriple-2            124776              9218 ns/op             912 B/op          4 allocs/op
BenchmarkDESEncryptCBCTriple-2            125689              9566 ns/op            1008 B/op          7 allocs/op
BenchmarkDESEncryptCFBTriple-2            124815              9201 ns/op             736 B/op          6 allocs/op
BenchmarkDESEncryptOFBTriple-2             51578             23218 ns/op            1240 B/op          6 allocs/op
BenchmarkDESEncryptCTRTriple-2             50308             23723 ns/op            1240 B/op          6 allocs/op
BenchmarkDESDecryptECBTriple-2            126886              9149 ns/op             672 B/op          3 allocs/op
BenchmarkDESDecryptCBCTriple-2            125438              9386 ns/op             768 B/op          6 allocs/op
BenchmarkDESDecryptCFBTriple-2            129867              9106 ns/op             736 B/op          6 allocs/op
BenchmarkDESDecryptOFBTriple-2             51937             23120 ns/op            1240 B/op          6 allocs/op
BenchmarkDESDecryptCTRTriple-2             50586             23663 ns/op            1240 B/op          6 allocs/op

BenchmarkAESEncryptECB-2         2171973               521.7 ns/op          1104 B/op          7 allocs/op
BenchmarkAESEncryptCBC-2         1531668               783.4 ns/op          1216 B/op         10 allocs/op
BenchmarkAESEncryptCFB-2         1824134               695.9 ns/op           944 B/op          9 allocs/op
BenchmarkAESEncryptOFB-2          911320              1237 ns/op            1440 B/op          9 allocs/op
BenchmarkAESEncryptCTR-2          803710              1397 ns/op            1440 B/op          9 allocs/op
BenchmarkAESEncryptGCM-2         1809597               663.1 ns/op          1168 B/op          7 allocs/op
BenchmarkAESDecryptECB-2         2417019               499.7 ns/op           864 B/op          6 allocs/op
BenchmarkAESDecryptCBC-2         1593308               731.7 ns/op           976 B/op          9 allocs/op
BenchmarkAESDecryptCFB-2         1686566               704.9 ns/op           944 B/op          9 allocs/op
BenchmarkAESDecryptOFB-2          923946              1242 ns/op            1440 B/op          9 allocs/op
BenchmarkAESDecryptCTR-2          806540              1400 ns/op            1440 B/op          9 allocs/op
BenchmarkAESDecryptGCM-2         1894051               640.9 ns/op          1040 B/op          6 allocs/op

BenchmarkRSAEncryptPKCS1v15-2                       1201            959134 ns/op           95488 B/op        155 allocs/op
BenchmarkRSAEncryptOAEP-2                           1314            908112 ns/op           95592 B/op        160 allocs/op
BenchmarkRSADecryptPKCS1v15-2                        165           7231858 ns/op            7600 B/op         16 allocs/op
BenchmarkRSADecryptPKCS1v15SessionKey-2              165           7258559 ns/op            7600 B/op         16 allocs/op
BenchmarkRSADecryptOAEP-2                            163           7259562 ns/op            7704 B/op         21 allocs/op
BenchmarkRSASignPSS-2                                153           7767465 ns/op           67168 B/op        100 allocs/op
BenchmarkRSASignPKCS1v15-2                           153           7716531 ns/op           66992 B/op         95 allocs/op
BenchmarkRSAVerifyPSS-2                             1299            900510 ns/op           95184 B/op        159 allocs/op
BenchmarkRSAVerifyPKCS1v15-2                        1342            895322 ns/op           94976 B/op        154 allocs/op

BenchmarkRSAGenerateKey1024PKCS1PKIX-2                49          21338527 ns/op         1079991 B/op       4199 allocs/op
BenchmarkRSAGenerateKey2048PKCS1PKIX-2                10         144698482 ns/op         2365458 B/op       6320 allocs/op
BenchmarkRSAGenerateKey4096PKCS1PKIX-2                 1        1768958872 ns/op         8226112 B/op      13412 allocs/op
BenchmarkRSAGenerateKey1024PKCS8PKIX-2                69          22087393 ns/op         1108224 B/op       4311 allocs/op
BenchmarkRSAGenerateKey2048PKCS8PKIX-2                14         172734660 ns/op         2903737 B/op       7676 allocs/op
BenchmarkRSAGenerateKey4096PKCS8PKIX-2                 2        1555430436 ns/op         7282760 B/op      12011 allocs/op
BenchmarkRSAGenerateKey1024PKCS1PKCS1-2               56          19183225 ns/op          955589 B/op       3754 allocs/op
BenchmarkRSAGenerateKey2048PKCS1PKCS1-2                6         167403112 ns/op         2785446 B/op       7325 allocs/op
BenchmarkRSAGenerateKey4096PKCS1PKCS1-2                1        1423955024 ns/op         6611904 B/op      10909 allocs/op
BenchmarkRSAGenerateKey1024PKCS8PKCS1-2               56          19598088 ns/op          984203 B/op       3885 allocs/op
BenchmarkRSAGenerateKey2048PKCS8PKCS1-2                6         178566556 ns/op         3021040 B/op       7946 allocs/op
BenchmarkRSAGenerateKey4096PKCS8PKCS1-2                2        1060629315 ns/op         4823856 B/op       8048 allocs/op
```

### 🎨 Contributing

If you find that something is not working as expected please open an _**issue**_.
