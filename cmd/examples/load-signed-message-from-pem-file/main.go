// Программа демонстрирует загрузку подписи сообщения GOST3410 из файла в формате PEM
package main

import (
	signedmessage "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message"
	"github.com/nobuenhombre/suikat/pkg/colorog"
	"github.com/nobuenhombre/suikat/pkg/dates"

	"github.com/nobuenhombre/suikat/pkg/ge"
)

var log = colorog.NewColoredLog(true, dates.DateTimeFormatDashYYYYMMDDHHmmss)

func main() {
	log.Messageln("DEMO: Read GOST3410 signed message from PEM file")

	messageContainer, err := signedmessage.DecodePEMFile("message.txt.sign")
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	log.Infof("Signed Message [%#v]\n", messageContainer)
}
