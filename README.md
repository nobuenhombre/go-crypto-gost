This is FORK multiple cryptographics libraries

1. https://git.cypherpunks.ru/gogost.git
2. https://github.com/ftomza/go-gost-crypto.git
3. https://github.com/ddulesov/pkcs7

4. Pure Go GOST cryptographic functions library.

GOST is GOvernment STandard of Russian Federation (and Soviet Union).

* GOST 28147-89 (RFC 5830) block cipher with ECB, CNT (CTR), CFB, MAC
  CBC (RFC 4357) modes of operation
* various 28147-89-related S-boxes included
* GOST R 34.11-94 hash function (RFC 5831)
* GOST R 34.11-2012 Стрибог (Streebog) hash function (RFC 6986)
* GOST R 34.10-2001 (RFC 5832) public key signature function
* GOST R 34.10-2012 (RFC 7091) public key signature function
* various 34.10 curve parameters included
* Coordinates conversion from twisted Edwards to Weierstrass form and
  vice versa
* VKO GOST R 34.10-2001 key agreement function (RFC 4357)
* VKO GOST R 34.10-2012 key agreement function (RFC 7836)
* KDF_GOSTR3411_2012_256 KDF function (RFC 7836)
* GOST R 34.12-2015 128-bit block cipher Кузнечик (Kuznechik) (RFC 7801)
* GOST R 34.12-2015 64-bit block cipher Магма (Magma)
* GOST R 34.13-2015 padding methods
* MGM AEAD mode for 64 and 128 bit ciphers (RFC 9058)
* TLSTREE keyscheduling function
* ESPTREE/IKETREE (IKE* is the same as ESP*) keyscheduling function
* PRF_IPSEC_PRFPLUS_GOSTR3411_2012_{256,512} and generic prf+ functions
  (Р 50.1.111-2016 with IKEv2 RFC 7296)

Probably you could be interested in
Go's support of GOST TLS 1.3 (http://www.gostls13.cypherpunks.ru/).

Known problems:

* intermediate calculation values are not zeroed
* 34.10 is not time constant and slow

Example 34.10-2012-256 keypair generation, signing and verifying:
See in folder /examples

GoGOST is free software: see the file COPYING for copying conditions.

GoGOST'es home page is: http://www.gogost.cypherpunks.ru/
You can read about GOST algorithms more: http://www.gost.cypherpunks.ru/

Please send questions, bug reports and patches to
http://lists.cypherpunks.ru/gost.html mailing list.
Announcements also go to this mailing list.

Development Git source code repository currently is located here:
http://www.git.cypherpunks.ru/?p=gogost.git;a=summary

Fork date 16-02-2022


2. Module for reading certificates and private key in DER format with GOST algorithms

Fork date 16-02-2022

3. ## CMS (Cryptographic Message Syntax) Golang library with  GOST cryptography support
[![Build Status](https://travis-ci.com/ddulesov/pkcs7.svg?branch=master)](https://travis-ci.com/ddulesov/pkcs7)

designed primarily for [Rutoken](https://www.rutoken.ru/products/all/rutoken-ecp/)  authentication
[Rutoken Plugin Doc](https://dev.rutoken.ru/display/PUB/RutokenPluginDoc)

## based on  RFC5652 CMS syntax.
verifies **encapContentInfo** signature with messageDigest
verifies **SigningTime**  in the range notBefore - notAfter
verifies **SignedAttributes** that signature is valid
verifies attached **certificates**  that it has valid ca signature


## Features
- GOST R 34.11-94 hash function (RFC 5831)
- GOST R 34.11-2012 Стрибог (Streebog) hash function (RFC 6986)
- GOST R 34.10-2001 (RFC 5832) public key signature function
- GOST R 34.10-2012 256 and 512 bit (RFC 7091) public key signature function
- as well as RSA with SHA256/SHA512
- DSA , ECDSA, RSA PSS not supported
- Validate Content Data, Signing time, Signers certificates against provided CA

## Issues
implement only [Signed-data Content Type](https://tools.ietf.org/html/rfc5652#section-5.1).
ignore signature algorithm parameters (use only GOST A-ParamSets)

## See documentation
- https://tc26.ru/
- https://datatracker.ietf.org/doc/rfc4491/?include_text=1
- https://tools.ietf.org/html/rfc5652#page-13
- https://www.cryptopro.ru/sites/default/files/products/tls/tk26iok.pdf
- https://www.streebog.net/en/

## GOST crypto algogithms oids
https://cpdn.cryptopro.ru/content/csp40/html/group___pro_c_s_p_ex_CP_PARAM_OIDS.html
http://cpdn.cryptopro.ru/content/csp36/html/group___pro_c_s_p_ex_DP8.html

## Requirements
* Go 1.11 or higher.
* gogost https://github.com/ddulesov/gogost

## Installation

Install:

```shell
go get -u github.com/ddulesov/pkcs7
```

Import:

```go
import "github.com/ddulesov/pkcs7"
```


## Quickstart

```go
package main

import (
	"log"
	"os"
	"github.com/ddulesov/pkcs7"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"time"
)

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func loadCertificatesFromFile(filename string) ([]*pkcs7.Certificate, error) {
	var ber *pem.Block
	buff, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	calist := make([]*pkcs7.Certificate, 0)

	for len(buff) > 0 {

		ber, buff = pem.Decode(buff)
		if ber == nil || ber.Type != "CERTIFICATE" {
			return nil, errors.New("invalid certificate file format")
		}
		ca, err := pkcs7.ParseCertificate(ber.Bytes)
		if err != nil {
			return nil, err
		}
		calist = append(calist, ca)
		
	}

	return calist, nil
}

func main() {
	if len(os.Args) < 2 {
		log.Printf("%s <cms.file> <ca.cert>", os.Args[0])
		return
	}

	file := os.Args[1]
	buff, err := ioutil.ReadFile(file)
	check(err)

	ber, _ := pem.Decode(buff)
	if ber == nil || ber.Type != "CMS" {
		log.Fatal("not PEM encoded")
	}

	cms, err := pkcs7.ParseCMS(ber.Bytes)
	check(err)

	file = os.Args[2]

	calist, err := loadCertificatesFromFile(file)
	check(err)

	err = cms.VerifyCertificates(calist)
	check(err)

	time1 := time.Date(2019, time.August, 23, 0, 0, 0, 0, time.UTC)
	time2 := time.Date(2019, time.August, 25, 0, 0, 0, 0, time.UTC)

	data := []byte{116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103, 10}

	err = cms.Verify(data, time1, time2)
	check(err)

	log.Printf("%s valid!", os.Args[1])

}
```


## Tools
PEM encoded certificates, cms, csr online viewer
http://gostcrypto.com/tool-asn1.html

 
LITERATURE
https://www.altlinux.org/OSS-GOST-Crypto
//GOST-R  https://www.cryptopro.ru/sites/default/files/products/tls/tk26iok.pdf