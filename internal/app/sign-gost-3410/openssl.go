package signGost3410

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

func PKCS7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func PKCS7UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

//plainText := []byte(text)
//key, _ := hex.DecodeString(keyStr)
//iv, _ := hex.DecodeString(ivStr)

func OpensslEncrypt(key, iv, plainText []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	blockSize := block.BlockSize()
	origData := PKCS7Padding(plainText, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cryted := make([]byte, len(origData))
	blockMode.CryptBlocks(cryted, origData)

	return cryted, nil
}

//return fmt.Sprintf("%x\n", ciphertext)

//key, _ := hex.DecodeString(keyStr)
//iv, _ := hex.DecodeString(ivStr)
//plainText, _ := hex.DecodeString(text)

func OpensslDecrypt(key, iv, cipherText []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData = PKCS7UnPadding(origData)

	return origData, nil
}

//return fmt.Sprintf("%s\n", plaintext)
