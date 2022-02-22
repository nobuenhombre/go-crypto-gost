// Программа демонстрирует работу GOST алгоритмов
// C использованием PKCSx контейнеров

package main

import (
	"crypto/rand"
	readGost3410CertPem "github.com/nobuenhombre/go-crypto-gost/internal/app/read-gost-3410-cert-pem"
	signGost3410 "github.com/nobuenhombre/go-crypto-gost/internal/app/sign-gost-3410"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	privateKey "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/private-key"
	signedMessage "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/hash"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/pkcs7gost"
	"github.com/nobuenhombre/suikat/pkg/fico"
	"github.com/nobuenhombre/suikat/pkg/ge"
	"log"
	"reflect"
)

func main() {
	keysPath := "keys/old/"
	messagesPath := "messages/original/"

	// 1. Получаем конфигурацию из командной строки
	//---------------------------------------------
	cfg := &readGost3410CertPem.CliConfig{}

	err := cfg.Load()
	if err != nil {
		log.Fatalf("CLI config error [%v]", err)
	}

	log.Printf("config = %#v", cfg)

	// 2. Загружаем Приватный ключ из файла
	//-------------------------------------
	gost3410PrivateKey, err := privateKey.NewPrivateKeyFromFile(keysPath + cfg.PrivateKeyFile)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// 3. Извлекаем Публичный ключ из Приватного
	//------------------------------------------
	gost3410PublicKey, err := gost3410PrivateKey.PublicKey()
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	log.Printf("gost3410PrivateKey = %#v, \n gost3410PublicKey = %#v", gost3410PrivateKey, gost3410PublicKey)

	// 4. Загружаем Публичный ключ из Файла который есть на диске
	//-----------------------------------------------------------
	certificate, err := certificate.NewCertificatesFromFile(keysPath + cfg.PublicKeyFile)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	gost3410PublicKeyCertificate, err := certificate[0].TBSCertificate.PublicKeyInfo.GetPublicKey()
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	log.Printf("gost3410PublicKey = %#v \n containerGostPublicKey = %#v", gost3410PublicKey, gost3410PublicKeyCertificate)

	if !reflect.DeepEqual(gost3410PublicKey, gost3410PublicKeyCertificate) {
		log.Fatalln("Public key Restored from Private key (private.key.pem) - HAVE difference with Public key Loaded from public.key.pem")
	}

	//// 5. Загрузим готовую подпись из файла
	////-------------------------------------
	message, err := signedMessage.NewCryptoMessageFromFile(messagesPath + cfg.MessageFileSign)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	log.Println(message)

	//notBefore := time.Date(2021, time.September, 1, 0, 0, 0, 0, dates.GetSamaraLocation())
	//notAfter := time.Date(2022, time.January, 1, 0, 0, 0, 0, dates.GetSamaraLocation())
	//err = message.Verify([]byte{}, notBefore, notAfter)
	//if err != nil {
	//	log.Fatal(ge.Pin(err))
	//}

	// 6. Пробуем Сгенерировать подпись из исходного сообщения
	//--------------------------------------------------------
	sourceMessageFile := fico.TxtFile(messagesPath + cfg.MessageFile)
	sourceMessage, err := sourceMessageFile.ReadBytes()
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	//// 6.2. Создаем Хеш Данных - Дайджест
	digest, err := signGost3410.GetDigest(sourceMessage, hash.GostR34112012256)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// 6. Подписываем Дайджест (хеш от данных) Приватным Ключом
	signDigest, err := gost3410PrivateKey.Sign(rand.Reader, digest, nil)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// My signature is not validated by other implementations. What is wrong?
	// - Try to reverse SIGNATURE (like sign[::-1] in Python).
	// - Try to swap SIGNATURE halves (sign[len(sign)/2:] + sign[:len(sign)/2]).
	// - Try to reverse SIGNATURE swapped halves too.
	//
	// My signature is still not validated by other implementations!
	// - Try to reverse DIGEST you are signing/verifying (like dgst[::-1] in Python).
	//
	// Everything above did not help me. Does GoGOST sucks?
	// No way! You still have not tried
	// - Try to reverse your binary private key,
	// - Try to reverse your binary public key,
	// - Try to swap halves your binary private key,
	// - Try to swap halves your binary public key,
	//
	// It is GOST: do you expect serialization unification?!

	// 7. Проверяем соответствие Подписи и Дайджеста при помощи Публичного ключа
	isValidSignDigest, err := gost3410PublicKeyCertificate.VerifyDigest(digest, signDigest)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	if !isValidSignDigest {
		log.Fatal("signature digest is invalid")
	}

	// 7. Пробуем сравнить подписи message и signDigest

	//gost3410PrivateKey.
	//
	//
	//isValidSignDigestCMS, err := gost3410PublicKeyCertificate.VerifyDigest(digest, message.GetEncryptedDigest())
	//if err != nil {
	//	log.Fatal(ge.Pin(err))
	//}
	//
	//if !isValidSignDigestCMS {
	//	log.Fatal("signature digest is invalid CMS")
	//}

	signPKCS7, err := pkcs7gost.SignAndDetach(sourceMessage, certificate[0], gost3410PrivateKey)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	outSignedFile := fico.TxtFile(messagesPath + "test." + cfg.MessageFileSign)

	err = outSignedFile.Write(string(signPKCS7))
	if err != nil {
		log.Fatal(ge.Pin(err))
	}
}
