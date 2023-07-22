# 🔒 Cryptox

[![Go Doc](_icons/godoc.svg)](https://pkg.go.dev/github.com/FishGoddess/cryptox)
[![License](_icons/license.svg)](https://opensource.org/licenses/MIT)
[![Coverage](_icons/coverage.svg)](_icons/coverage.svg)
![Test](https://github.com/FishGoddess/cryptox/actions/workflows/test.yml/badge.svg)

**Cryptox** is a kit for safety which includes some common encrypted/decrypted algorithms.

[阅读中文版的文档](./README.md)

### 💡 Features

* HEX/BASE64 Supports.
* MD5/SHA1/SHA256/SHA512/HMAC Supports.
* CRC/FNV Supports.
* DES/3DES/AES Supports.
* RSA/ECC Supports.
* ECB/CBC/OFB/CFB/CTR Supports.
* PKCS5/PKCS7/ZERO/NO Supports.

_Check [HISTORY.md](./HISTORY.md) and [FUTURE.md](./FUTURE.md) to know about more information._

### ⚙ How to use

```shell
$ go get -u github.com/FishGoddess/cryptox
```

* [hash](_examples/hash.go)
* [des](_examples/des.go)
* [triple_des](_examples/triple_des.go)
* [aes](_examples/aes.go)
* [rsa_key](_examples/rsa_key.go)
* [rsa](_examples/rsa.go)

### 🚴🏻 Benchmarks

```shell
$ make bench
```

_Note: Data size is 128 bytes, ecb/cbc uses pkcs7 padding, cfb/ofb/ctr is no padding._

```
goos: darwin
goarch: amd64
cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz

BenchmarkMD5-12                 11118327                111.2 ns/op             0 B/op          0 allocs/op
BenchmarkSHA1-12                 9216342                129.3 ns/op             0 B/op          0 allocs/op
BenchmarkSHA224-12               6227264                219.6 ns/op             0 B/op          0 allocs/op
BenchmarkSHA256-12               5364110                203.8 ns/op             0 B/op          0 allocs/op
BenchmarkSHA384-12               4600442                254.7 ns/op             0 B/op          0 allocs/op
BenchmarkSHA512-12               4683705                266.1 ns/op             0 B/op          0 allocs/op
BenchmarkHMAC-12                  929726                 1156 ns/op           512 B/op          6 allocs/op
BenchmarkCRC32IEEE-12           53518428                25.81 ns/op             0 B/op          0 allocs/op
BenchmarkCRC64ISO-12            47010480                23.54 ns/op             0 B/op          0 allocs/op
BenchmarkCRC64ECMA-12           51956055                23.19 ns/op             0 B/op          0 allocs/op
BenchmarkFnv32-12              104025846                12.84 ns/op             0 B/op          0 allocs/op
BenchmarkFnv32a-12              89485070                12.40 ns/op             0 B/op          0 allocs/op
BenchmarkFnv64-12               68797173                15.69 ns/op             0 B/op          0 allocs/op
BenchmarkFnv64a-12              78190952                16.05 ns/op             0 B/op          0 allocs/op
BenchmarkFnv128-12              17743756                63.86 ns/op            16 B/op          1 allocs/op
BenchmarkFnv128a-12             19056975                64.67 ns/op            16 B/op          1 allocs/op

BenchmarkDESEncryptECB-12    	  704928	      1724 ns/op	     528 B/op	       3 allocs/op
BenchmarkDESEncryptCBC-12    	  615673	      1906 ns/op	     624 B/op	       6 allocs/op
BenchmarkDESEncryptCFB-12    	  621673	      1918 ns/op	     624 B/op	       6 allocs/op
BenchmarkDESEncryptOFB-12    	  194791	      6283 ns/op	    1128 B/op	       6 allocs/op
BenchmarkDESEncryptCTR-12    	  180862	      6512 ns/op	    1128 B/op	       6 allocs/op
BenchmarkDESDecryptECB-12    	  727572	      1660 ns/op	     144 B/op	       1 allocs/op
BenchmarkDESDecryptCBC-12    	  607128	      1853 ns/op	     240 B/op	       4 allocs/op
BenchmarkDESDecryptCFB-12    	  654042	      1724 ns/op	     224 B/op	       4 allocs/op
BenchmarkDESDecryptOFB-12    	  198878	      5928 ns/op	     728 B/op	       4 allocs/op
BenchmarkDESDecryptCTR-12    	  181810	      6323 ns/op	     728 B/op	       4 allocs/op

BenchmarkTripleDESEncryptECB-12    	  254095	      4018 ns/op	     528 B/op	       3 allocs/op
BenchmarkTripleDESEncryptCBC-12    	  278199	      4301 ns/op	     624 B/op	       6 allocs/op
BenchmarkTripleDESEncryptCFB-12    	  295966	      4037 ns/op	     352 B/op	       5 allocs/op
BenchmarkTripleDESEncryptOFB-12    	   80428	     14864 ns/op	     856 B/op	       5 allocs/op
BenchmarkTripleDESEncryptCTR-12    	   78086	     15311 ns/op	     856 B/op	       5 allocs/op
BenchmarkTripleDESDecryptECB-12    	  289245	      4018 ns/op	     144 B/op	       1 allocs/op
BenchmarkTripleDESDecryptCBC-12    	  283914	      4232 ns/op	     240 B/op	       4 allocs/op
BenchmarkTripleDESDecryptCFB-12    	  301969	      3958 ns/op	     224 B/op	       4 allocs/op
BenchmarkTripleDESDecryptOFB-12    	   79599	     15109 ns/op	     728 B/op	       4 allocs/op
BenchmarkTripleDESDecryptCTR-12    	   75466	     15411 ns/op	     728 B/op	       4 allocs/op

BenchmarkAESEncryptECB-12        4806080               266.4 ns/op           528 B/op          3 allocs/op
BenchmarkAESEncryptCBC-12        2538808               471.7 ns/op           640 B/op          6 allocs/op
BenchmarkAESEncryptCFB-12        2787636               400.0 ns/op           368 B/op          5 allocs/op
BenchmarkAESEncryptOFB-12        1536372               790.4 ns/op           864 B/op          5 allocs/op
BenchmarkAESEncryptCTR-12        1303022               924.3 ns/op           864 B/op          5 allocs/op
BenchmarkAESEncryptGCM-12        3683218               330.1 ns/op           592 B/op          3 allocs/op
BenchmarkAESDecryptECB-12        8220330               143.1 ns/op           144 B/op          1 allocs/op
BenchmarkAESDecryptCBC-12        3690129               312.8 ns/op           256 B/op          4 allocs/op
BenchmarkAESDecryptCFB-12        3557036               329.2 ns/op           240 B/op          4 allocs/op
BenchmarkAESDecryptOFB-12        1649554               736.8 ns/op           736 B/op          4 allocs/op
BenchmarkAESDecryptCTR-12        1369501               869.6 ns/op           736 B/op          4 allocs/op
BenchmarkAESDecryptGCM-12        4053975               287.9 ns/op           464 B/op          2 allocs/op

BenchmarkRSAGenerateKey1024PKCS1PKIX-12     	      66	  16759624 ns/op	 1026852 B/op	    4042 allocs/op
BenchmarkRSAGenerateKey2048PKCS1PKIX-12     	      13	 113534778 ns/op	 2129219 B/op	    5761 allocs/op
BenchmarkRSAGenerateKey4096PKCS1PKIX-12     	       1	1488439897 ns/op	 7618600 B/op	   12531 allocs/op
BenchmarkRSAGenerateKey1024PKCS8PKIX-12     	     100	  18313053 ns/op	 1141365 B/op	    4446 allocs/op
BenchmarkRSAGenerateKey2048PKCS8PKIX-12     	       9	 112680007 ns/op	 2040232 B/op	    5580 allocs/op
BenchmarkRSAGenerateKey4096PKCS8PKIX-12     	       1	1906389743 ns/op	 9639848 B/op	   15813 allocs/op
BenchmarkRSAGenerateKey1024PKCS1PKCS1-12    	      62	  17034143 ns/op	 1049731 B/op	    4087 allocs/op
BenchmarkRSAGenerateKey2048PKCS1PKCS1-12    	       6	 168170768 ns/op	 3244070 B/op	    8506 allocs/op
BenchmarkRSAGenerateKey4096PKCS1PKCS1-12    	       1	3351513226 ns/op	17279344 B/op	   28016 allocs/op
BenchmarkRSAGenerateKey1024PKCS8PKCS1-12    	      85	  16348451 ns/op	 1002687 B/op	    3963 allocs/op
BenchmarkRSAGenerateKey2048PKCS8PKCS1-12    	      10	 156983244 ns/op	 2981515 B/op	    7870 allocs/op
BenchmarkRSAGenerateKey4096PKCS8PKCS1-12    	       2	1858173339 ns/op	 9579004 B/op	   15697 allocs/op

BenchmarkRSAEncryptPKCS1v15-12                     24886             47889 ns/op            5119 B/op         12 allocs/op
BenchmarkRSAEncryptOAEP-12                         25232             47543 ns/op            5475 B/op         18 allocs/op
BenchmarkRSADecryptPKCS1v15-12                       952           1278215 ns/op           26179 B/op        102 allocs/op
BenchmarkRSADecryptPKCS1v15SessionKey-12             938           1284501 ns/op           26181 B/op        102 allocs/op
BenchmarkRSADecryptOAEP-12                           910           1292574 ns/op           26279 B/op        107 allocs/op

BenchmarkRSASignPSS-12                               876           1334332 ns/op           31016 B/op        116 allocs/op
BenchmarkRSASignPKCS1v15-12                          886           1454273 ns/op           30578 B/op        110 allocs/op
BenchmarkRSAVerifyPSS-12                           23065             45778 ns/op            5323 B/op         17 allocs/op
BenchmarkRSAVerifyPKCS1v15-12                      27355             46102 ns/op            5115 B/op         12 allocs/op
```

### 🎨 Contributing

If you find that something is not working as expected please open an _**issue**_.

### 💪 Projects using cryptox

| Project | Author     | Description                                    | link                                                                                          |
|---------|------------|------------------------------------------------|-----------------------------------------------------------------------------------------------|
| Postar  | avino-plan | An easy-to-use and low-coupling email service. | [Github](https://github.com/avino-plan/postar) / [Gitee](https://gitee.com/avino-plan/postar) |

At last, I want to thank JetBrains for **free JetBrains Open Source license(s)**, because cryptox is developed with Idea
/ GoLand under it.

<a href="https://www.jetbrains.com/?from=cryptox" target="_blank"><img src="./_icons/jetbrains.png" width="250"/></a>