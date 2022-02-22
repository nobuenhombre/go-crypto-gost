// Программа демонстрирует работу GOST алгоритмов
// Без использования PKCSx контейнеров
// [COMPLETED]

package main

import (
	"crypto/rand"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/curves"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/hash"
	"log"

	signGost3410 "github.com/nobuenhombre/go-crypto-gost/internal/app/sign-gost-3410"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

func main() {
	// 1. Создаем Данные
	data := []byte("data to be signed")

	// 2. Создаем Хеш Данных - Дайджест
	digest, err := signGost3410.GetDigest(data, hash.GostR34112012256)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// 3. Создаем кривую
	curveOid := oids.Tc26Gost34102012256ParamSetB
	curve, err := curves.Get(curveOid)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// 4. Генерируем Приватный ключ
	privateKey, err := signGost3410.GeneratePrivateKey(curve)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// 5. Извлекаем из Приватного ключа -> Публичный
	publicKeyGost, err := signGost3410.ExtractPublicKeyGOST(curve, privateKey)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// 6. Подписываем Дайджест (хеш от данных) Приватным Ключом
	signDigest, err := privateKey.Sign(rand.Reader, digest, nil)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	// 7. Проверяем соответствие Подписи и Дайджеста при помощи Публичного ключа
	isValidSignDigest, err := publicKeyGost.VerifyDigest(digest, signDigest)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	if !isValidSignDigest {
		log.Fatal("signature digest is invalid")
	}
}
