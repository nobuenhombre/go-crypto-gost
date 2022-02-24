package rawCertificates

import (
	"encoding/asn1"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

func (raw *RawCertificates) EncodeToCertificates() ([]*certificate.Certificate, error) {
	var v []*certificate.Certificate

	if len(raw.Raw) == 0 {
		return nil, ge.Pin(nil)
	}

	var val asn1.RawValue
	_, err := asn1.Unmarshal(raw.Raw, &val)
	if err != nil {
		return nil, ge.Pin(err)
	}

	asn1Data := val.Bytes

	//for len(asn1Data) > 0 {
	certs, err := certificate.NewCertificatesFromDER(asn1Data)
	if err != nil {
		return nil, ge.Pin(err)
	}

	//cert := new(Certificate)
	//
	//var err error
	//
	//asn1Data, err = asn1.Unmarshal(asn1Data, cert)
	//if err != nil {
	//	return nil, ge.Pin(err)
	//}

	v = append(v, certs...)
	//}

	return v, nil
}
