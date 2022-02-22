package certificate

import (
	"encoding/asn1"
	"encoding/pem"
	pemFormat "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/pem-format"
	"github.com/nobuenhombre/suikat/pkg/fico"
	"github.com/nobuenhombre/suikat/pkg/ge"
	"github.com/nobuenhombre/suikat/pkg/inslice"
)

// NewCertificatesFromDER parses a single certificate from the given ASN.1 DER data.
func NewCertificatesFromDER(derData []byte) ([]*Certificate, error) {
	var result []*Certificate

	data := derData
	for len(data) > 0 {
		var err error

		cert := &Certificate{}

		data, err = asn1.Unmarshal(data, cert)
		if err != nil {
			return nil, ge.Pin(err)
		}

		result = append(result, cert)
	}

	return result, nil
}

func NewCertificatesFromPEM(pemData []byte) ([]*Certificate, error) {
	var der *pem.Block

	buffer := pemData
	allow := []string{pemFormat.Certificate}

	result := make([]*Certificate, 0)

	for len(buffer) > 0 {
		der, buffer = pem.Decode(pemData)
		if der == nil || !inslice.String(der.Type, &allow) {
			return nil, ge.Pin(&ge.MismatchError{
				ComparedItems: "der.Type",
				Expected:      allow,
				Actual:        der.Type,
			})
		}

		certs, err := NewCertificatesFromDER(der.Bytes)
		if err != nil {
			return nil, ge.Pin(err)
		}

		result = append(result, certs...)
	}

	return result, nil
}

func NewCertificatesFromFile(file string) ([]*Certificate, error) {
	txtFile := fico.TxtFile(file)
	pem, err := txtFile.ReadBytes()
	if err != nil {
		return nil, ge.Pin(err)
	}

	return NewCertificatesFromPEM(pem)
}
