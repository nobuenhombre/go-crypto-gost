package signerinfo

import (
	"encoding/asn1"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers"

	"github.com/nobuenhombre/suikat/pkg/ge"
)

// Attribute asn.1 CMS
// RFC5652
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

func EncodeAttributeSliceToDER(attrs []Attribute) ([]byte, error) {
	encodedAttributes, err := asn1.Marshal(struct {
		A []Attribute `asn1:"set"`
	}{A: attrs})
	if err != nil {
		return nil, ge.Pin(err)
	}

	// Remove the leading sequence octets
	var raw asn1.RawValue

	rest, err := asn1.Unmarshal(encodedAttributes, &raw)
	if err != nil {
		return nil, ge.Pin(err)
	}

	if len(rest) > 0 {
		return nil, ge.Pin(&containers.TrailingDataError{})
	}

	return raw.Bytes, nil
}
