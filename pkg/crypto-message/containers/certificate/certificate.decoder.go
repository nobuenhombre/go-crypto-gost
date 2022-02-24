package certificate

import (
	"encoding/asn1"
	"encoding/pem"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers"

	"github.com/nobuenhombre/suikat/pkg/fico"
	"github.com/nobuenhombre/suikat/pkg/ge"
	"github.com/nobuenhombre/suikat/pkg/inslice"
)

// DecodeDER
// en: parses a multiple certificates from the given ASN.1 DER data.
// ru: парсит DER данные и выдает слайс сертификатов
func DecodeDER(derData containers.DER) ([]*Container, error) {
	var result []*Container

	data := derData
	for len(data) > 0 {
		var err error

		cert := &Container{}

		data, err = asn1.Unmarshal(data, cert)
		if err != nil {
			return nil, ge.Pin(err)
		}

		result = append(result, cert)
	}

	return result, nil
}

// DecodePEM
// en: parses a multiple certificates from the given ASN.1 PEM data.
// ru: парсит PEM данные и выдает слайс сертификатов
func DecodePEM(pemData containers.PEM) ([]*Container, error) {
	var der *pem.Block

	buffer := pemData
	allow := []string{containers.Certificate}

	result := make([]*Container, 0)

	for len(buffer) > 0 {
		der, buffer = pem.Decode(pemData)
		if der == nil || !inslice.String(der.Type, &allow) {
			return nil, ge.Pin(&ge.MismatchError{
				ComparedItems: "der.Type",
				Expected:      allow,
				Actual:        der.Type,
			})
		}

		certs, err := DecodeDER(der.Bytes)
		if err != nil {
			return nil, ge.Pin(err)
		}

		result = append(result, certs...)
	}

	return result, nil
}

// DecodePEMFile
// en: parses a multiple certificates from the given ASN.1 PEM file.
// ru: парсит указанный файл в формате PEM и возвращает слайс сертификатов
func DecodePEMFile(file string) ([]*Container, error) {
	txtFile := fico.TxtFile(file)

	pem, err := txtFile.ReadBytes()
	if err != nil {
		return nil, ge.Pin(err)
	}

	return DecodePEM(pem)
}
