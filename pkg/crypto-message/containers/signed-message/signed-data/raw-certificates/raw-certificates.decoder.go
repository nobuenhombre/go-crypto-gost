package rawcertificates

import (
	"bytes"
	"encoding/asn1"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

// DecodeCertificatesContainer concat and wraps the certificates in the RawValue structure
func DecodeCertificatesContainer(certificates []*certificate.Container) (*Container, error) {
	var buf bytes.Buffer

	for _, cert := range certificates {
		_, err := buf.Write(cert.Raw)
		if err != nil {
			return nil, ge.Pin(err)
		}
	}

	var val = asn1.RawValue{Bytes: buf.Bytes(), Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true}

	b, err := asn1.Marshal(val)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return &Container{Raw: b}, nil
}
