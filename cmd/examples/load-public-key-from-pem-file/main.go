// Программа демонстрирует загрузку публичного ключа GOST3410 из файла в формате PEM
package main

import (
	"github.com/nobuenhombre/suikat/pkg/colorog"
	"github.com/nobuenhombre/suikat/pkg/dates"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

var log = colorog.NewColoredLog(true, dates.DateTimeFormatDashYYYYMMDDHHmmss)

func main() {
	log.Messageln("DEMO: Read GOST3410 public key from PEM file")

	caList, err := certificate.DecodePEMFile("public.key.pem")
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	log.Infof("Public Key [%#v]\n", *caList[0])
}
