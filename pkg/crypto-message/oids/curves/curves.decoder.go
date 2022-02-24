package curves

import (
	"encoding/asn1"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

type Parameters struct {
	PublicKeyParamSet asn1.ObjectIdentifier
	DigestParamSet    asn1.ObjectIdentifier `asn1:"optional"`
}

func DecodeDER(der containers.DER) (*gost3410.Curve, error) {
	var params Parameters

	rest, err := asn1.Unmarshal(der, &params)
	if err != nil {
		return nil, ge.Pin(err)
	}

	if len(rest) != 0 {
		return nil, ge.Pin(&containers.TrailingDataError{})
	}

	oidId, err := oids.GetID(params.PublicKeyParamSet)
	if err != nil {
		return nil, ge.Pin(err)
	}

	curve, err := Get(oidId)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return curve, nil
}
