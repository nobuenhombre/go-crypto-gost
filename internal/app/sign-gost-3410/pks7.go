package signGost3410

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

// https://pkg.go.dev/go.mozilla.org/pkcs7#section-readme
// https://github.com/mozilla-services/pkcs7/blob/master/pkcs7_test.go
// https://github.com/mozilla-services/pkcs7/blob/master/sign_test.go

// https://github.com/ddulesov/pkcs7

// http://www.cryptopro.ru/forum2/default.aspx?g=posts&m=121139
// https://pkg.go.dev/github.com/spacemonkeygo/openssl
// https://pkg.go.dev/github.com/spacemonkeygo/openssl#Certificate.Sign

// https://github.com/forgoer/openssl

// https://github.com/pedroalbanese/gogost
// https://github.com/pedroalbanese/gogost/blob/master/cmd/signer/main.go
// https://github.com/pedroalbanese/gosttk/blob/master/GOSTTk.pdf

func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func DesEncryption(key, iv, plainText []byte) ([]byte, error) {

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	origData := PKCS5Padding(plainText, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cryted := make([]byte, len(origData))
	blockMode.CryptBlocks(cryted, origData)

	return cryted, nil
}

func DesDecryption(key, iv, cipherText []byte) ([]byte, error) {

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData = PKCS5UnPadding(origData)

	return origData, nil
}

func Example() {
	originalText := "sysys"
	fmt.Println(originalText)
	mytext := []byte(originalText)

	key := []byte{0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC}
	iv := []byte{0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC}

	cryptoText, _ := DesEncryption(key, iv, mytext)
	fmt.Println(string(cryptoText))
	decryptedText, _ := DesDecryption(key, iv, cryptoText)
	fmt.Println(string(decryptedText))

}
