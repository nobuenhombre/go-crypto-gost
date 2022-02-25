// Программа демонстрирует создание подписи сообщения GOST3410 в формате PEM
package main

import (
	signByPEMBytes "github.com/nobuenhombre/go-crypto-gost/internal/app/sign-by-pem-bytes"
	commandLine "github.com/nobuenhombre/go-crypto-gost/internal/pkg/command-line"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/services/sign"
	"github.com/nobuenhombre/suikat/pkg/colorog"
	"github.com/nobuenhombre/suikat/pkg/dates"
	"github.com/nobuenhombre/suikat/pkg/fico"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

var log = colorog.NewColoredLog(true, dates.DateTimeFormatDashYYYYMMDDHHmmss)

func main() {
	log.Messageln("DEMO: Create sign by GOST3410 with Public and Private keys stored in PEM files")
	// 1.
	// en: Read config from command line
	// ru: Получаем конфигурацию из командной строки
	// example command line params:
	// -PrivateKeyFile=keys/private.key.pem -PublicKeyFile=keys/public.key.pem \
	// -MessageFile=messages/message.txt -MessageFileSign=messages/message.txt.sign
	//---------------------------------------------
	cfg := &commandLine.Config{}

	err := cfg.Load()
	if err != nil {
		log.Fatalf("CLI config error [%v]", err)
	}

	log.Infof("config = %v \n", cfg)

	// 2.
	// en: Read bytes from files
	// ru: Прочитаем байты из файлов
	sourceMessage, publicKeyPEMBytes, privateKeyPEMBytes, err := signByPEMBytes.GetBytes(cfg)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// 3.
	// en: Sign message
	// ru: Подписываем сообщение
	signService := sign.New()
	signedMessagePEMBytes, err := signService.Sign(sourceMessage, publicKeyPEMBytes, privateKeyPEMBytes)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// 4.
	// en: Save Signed message in file
	// ru: Сохраняем Подписанное сообщение в файл
	outSignedFile := fico.TxtFile(cfg.MessageFileSign)
	err = outSignedFile.Write(string(signedMessagePEMBytes))
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// 5.
	// en: Signed message can be verified at site
	// ru: Подписанное сообщение можно проверить на сайте
	// https://crypto.kontur.ru/verify
	log.Successln("Your message signed")
	log.Infoln("Please verify it on https://crypto.kontur.ru/verify")
}
