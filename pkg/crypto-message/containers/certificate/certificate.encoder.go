package certificate

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"log"

	pemFormat "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers"

	"github.com/nobuenhombre/suikat/pkg/ge"
)

func (c *Certificate) EncodeToDER() ([]byte, error) {
	derData, err := asn1.Marshal(*c)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return derData, nil
}

func (c *Certificate) EncodeToPEM() ([]byte, error) {
	derData, err := c.EncodeToDER()
	if err != nil {
		return nil, ge.Pin(err)
	}

	var buffer bytes.Buffer

	err = pem.Encode(&buffer, &pem.Block{Type: pemFormat.Certificate, Bytes: derData})
	if err != nil {
		log.Fatal(err)
	}

	return buffer.Bytes(), nil
}
