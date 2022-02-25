// Программа демонстрирует проверку соответствия дайджеста и подписи сообщения GOST3410 в формате PEM
package main

import (
	"crypto/rand"
	"reflect"

	signgost3410 "github.com/nobuenhombre/go-crypto-gost/internal/app/sign-gost-3410"
	commandline "github.com/nobuenhombre/go-crypto-gost/internal/pkg/command-line"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	privatekey "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/private-key"
	signedmessage "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/hash"
	"github.com/nobuenhombre/suikat/pkg/colorog"
	"github.com/nobuenhombre/suikat/pkg/dates"
	"github.com/nobuenhombre/suikat/pkg/fico"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

var log = colorog.NewColoredLog(true, dates.DateTimeFormatDashYYYYMMDDHHmmss)

func main() {
	log.Messageln("DEMO: Verify Sign with Digest from signed message file (GOST3410) with Public and Private keys stored in PEM files")
	// 1.
	// en: Read config from command line
	// ru: Получаем конфигурацию из командной строки
	// example command line params:
	// -PrivateKeyFile=keys/private.key.pem -PublicKeyFile=keys/public.key.pem \
	// -MessageFile=messages/message.txt -MessageFileSign=messages/message.txt.sign
	//---------------------------------------------
	cfg := &commandline.Config{}

	err := cfg.Load()
	if err != nil {
		log.Fatalf("CLI config error [%v]", err)
	}

	log.Infof("config = %v \n", cfg)

	// 2.
	// Загрузим файлы
	// 2.1 Исходное сообщение
	sourceMessageFile := fico.TxtFile(cfg.MessageFile)
	sourceMessage, err := sourceMessageFile.ReadBytes()
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// 2.1 Приватный ключ
	gost3410PrivateKeyFromFile, err := privatekey.DecodePEMFile(cfg.PrivateKeyFile)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// 2.2 Публичный ключ
	certificateList, err := certificate.DecodePEMFile(cfg.PublicKeyFile)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// 2.3 Подпись исходного сообщения
	messageContainer, err := signedmessage.DecodePEMFile(cfg.MessageFileSign)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// 3. Извлекаем Публичный ключ из Приватного и сравниваем с Публичным ключом из файла
	gost3410PublicKeyFromPrivate, err := gost3410PrivateKeyFromFile.PublicKey()
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	gost3410PublicKeyFromFile, err := certificateList[0].TBSCertificate.PublicKeyInfo.GetPublicKey()
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	if reflect.DeepEqual(gost3410PublicKeyFromPrivate, gost3410PublicKeyFromFile) {
		log.Successln("Loaded and Generated Public Keys Identical")
		log.Messagef("gost3410PublicKeyFromPrivate = %#v \n gost3410PublicKeyFromFile = %#v", gost3410PublicKeyFromPrivate, gost3410PublicKeyFromFile)
	} else {
		log.Fatalln("Public key Restored from Private key (private.key.pem) - HAVE difference with Public key Loaded from public.key.pem")
	}

	// 4. Создаем Хеш Исходного сообщения - Дайджест
	digest, err := signgost3410.GetDigest(sourceMessage, hash.GostR34112012256)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// 5. Подписываем Дайджест (хеш от данных) Приватным Ключом
	signDigest, err := gost3410PrivateKeyFromFile.Sign(rand.Reader, digest, nil)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// 6. Проверяем соответствие Созданной только что Подписи и Дайджеста при помощи Публичного ключа
	isValidSignDigest, err := gost3410PublicKeyFromFile.VerifyDigest(digest, signDigest)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	if isValidSignDigest {
		log.Successln("created signature VALID")
	} else {
		log.Fatal("created signature is INVALID")
	}

	// 7. Проверяем соответствие Подписи загруженной ИЗ ФАЙЛА и Дайджеста при помощи Публичного ключа
	isValidSignDigestCMS, err := gost3410PublicKeyFromFile.VerifyDigest(digest, messageContainer.GetEncryptedDigest())
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	if isValidSignDigestCMS {
		log.Successln("loaded CMS signature VALID")
	} else {
		log.Errorln("loaded CMS signature is invalid")
	}
}
