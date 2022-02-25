// Программа демонстрирует создание подписи GOST3410 без использования PKCSx контейнеров (PEM)
package main

import (
	"crypto/rand"

	"github.com/nobuenhombre/suikat/pkg/colorog"
	"github.com/nobuenhombre/suikat/pkg/dates"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/curves"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/hash"

	signgost3410 "github.com/nobuenhombre/go-crypto-gost/internal/app/sign-gost-3410"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

var log = colorog.NewColoredLog(true, dates.DateTimeFormatDashYYYYMMDDHHmmss)

func main() {
	log.Messageln("DEMO: Create GOST3410 sign")

	// 1. Создаем Данные
	data := []byte("data to be signed")
	log.Infof("data [%v]\n", data)

	// 2. Создаем Хеш Данных - Дайджест
	digest, err := signgost3410.GetDigest(data, hash.GostR34112012256)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}
	log.Infof("digest [%v]\n", digest)

	// 3. Создаем кривую
	curveOid := oids.Tc26Gost34102012256ParamSetB
	curve, err := curves.Get(curveOid)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}
	log.Infof("curve [%v]\n", curve)

	// 4. Генерируем Приватный ключ
	privateKey, err := signgost3410.GeneratePrivateKey(curve)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}
	log.Infof("privateKey [%v]\n", privateKey)

	// 5. Извлекаем из Приватного ключа -> Публичный
	publicKeyGost, err := signgost3410.ExtractPublicKeyGOST(curve, privateKey)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}
	log.Infof("publicKeyGost [%v]\n", publicKeyGost)

	// 6. Подписываем Дайджест (хеш от данных) Приватным Ключом
	signDigest, err := privateKey.Sign(rand.Reader, digest, nil)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}
	log.Infof("signDigest [%v]\n", signDigest)

	// 7. Проверяем соответствие Подписи и Дайджеста при помощи Публичного ключа
	isValidSignDigest, err := publicKeyGost.VerifyDigest(digest, signDigest)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	if !isValidSignDigest {
		log.Fatal("signature digest is invalid")
	}

	log.Successln("signature digest valid")
}
