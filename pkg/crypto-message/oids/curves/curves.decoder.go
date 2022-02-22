package curves

import (
	"encoding/asn1"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

type GostR34102012PublicKeyParameters struct {
	PublicKeyParamSet asn1.ObjectIdentifier
	DigestParamSet    asn1.ObjectIdentifier `asn1:"optional"`
}

// algoData pkix.AlgorithmIdentifier
// paramsData := algoData.Parameters.FullBytes

func NewCurveFromDER(derData []byte) (*gost3410.Curve, error) {
	var publicKeyParams GostR34102012PublicKeyParameters

	rest, err := asn1.Unmarshal(derData, &publicKeyParams)
	if err != nil {
		return nil, ge.New("x509: failed to parse GOST parameters")
	}

	if len(rest) != 0 {
		return nil, ge.New("x509: trailing data after GOST parameters")
	}

	oidId, err := oids.GetID(publicKeyParams.PublicKeyParamSet)
	if err != nil {
		return nil, ge.Pin(err)
	}

	curve, err := Get(oidId)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return curve, nil
}
