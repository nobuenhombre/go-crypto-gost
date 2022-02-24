package certificate

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

// EncodeToDER
// en: convert certificate to DER data.
// ru: конвертирует сертификат в DER данные
func (c *Container) EncodeToDER() (containers.DER, error) {
	derData, err := asn1.Marshal(*c)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return derData, nil
}

// EncodeToPEM
// en: convert certificate to PEM data.
// ru: конвертирует сертификат в PEM данные
func (c *Container) EncodeToPEM() (containers.PEM, error) {
	derData, err := c.EncodeToDER()
	if err != nil {
		return nil, ge.Pin(err)
	}

	var buffer bytes.Buffer

	err = pem.Encode(&buffer, &pem.Block{Type: containers.Certificate, Bytes: derData})
	if err != nil {
		return nil, ge.Pin(err)
	}

	return buffer.Bytes(), nil
}
