package rawcertificates

import (
	"encoding/asn1"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

func (raw *Container) EncodeToCertificates() ([]*certificate.Container, error) {
	var v []*certificate.Container

	if len(raw.Raw) == 0 {
		return nil, ge.Pin(nil)
	}

	var val asn1.RawValue

	_, err := asn1.Unmarshal(raw.Raw, &val)
	if err != nil {
		return nil, ge.Pin(err)
	}

	asn1Data := val.Bytes

	certs, err := certificate.DecodeDER(asn1Data)
	if err != nil {
		return nil, ge.Pin(err)
	}

	v = append(v, certs...)

	return v, nil
}
