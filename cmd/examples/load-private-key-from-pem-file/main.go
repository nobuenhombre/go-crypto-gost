// Программа демонстрирует загрузку приватного ключа GOST3410 из файла в формате PEM
package main

import (
	privatekey "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/private-key"
	"github.com/nobuenhombre/suikat/pkg/colorog"
	"github.com/nobuenhombre/suikat/pkg/dates"

	"github.com/nobuenhombre/suikat/pkg/ge"
)

var log = colorog.NewColoredLog(true, dates.DateTimeFormatDashYYYYMMDDHHmmss)

func main() {
	log.Messageln("DEMO: Read GOST3410 private key from PEM file")

	privateKey, err := privatekey.DecodePEMFile("private.key.pem")
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	log.Infof("Private Key [%#v]\n", *privateKey)
}
