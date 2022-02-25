package privatekey

import (
	"encoding/asn1"
	"encoding/pem"

	publickeyalgorithm "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm/public-key-algorithm"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/curves"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/fico"
	"github.com/nobuenhombre/suikat/pkg/ge"
	"github.com/nobuenhombre/suikat/pkg/inslice"
	"golang.org/x/crypto/cryptobyte"
	cryptobyteAsn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	Length     = 32
	ASN1Length = 34
)

func DecodeDER(derData containers.DER) (key *gost3410.PrivateKey, err error) {
	var privateKey Container

	if _, err := asn1.Unmarshal(derData, &privateKey); err != nil {
		return nil, ge.Pin(err)
	}

	oidID, err := oids.GetID(privateKey.Algorithm.Algorithm)
	if err != nil {
		return nil, ge.Pin(err)
	}

	algo, err := publickeyalgorithm.Get(oidID)
	if err != nil {
		return nil, ge.Pin(err)
	}

	switch algo {
	case publickeyalgorithm.GostR34102001, publickeyalgorithm.GostR34102012256, publickeyalgorithm.GostR34102012512:
		var privateKeyRaw []byte

		if len(privateKey.PrivateKey) == ASN1Length {
			s := cryptobyte.String(privateKey.PrivateKey)
			if !s.ReadASN1Bytes(&privateKeyRaw, cryptobyteAsn1.OCTET_STRING) {
				return nil, ge.New("x509: can not decode GOST public key")
			}
		} else {
			privateKeyRaw = privateKey.PrivateKey
		}

		curve, err := curves.DecodeDER(privateKey.Algorithm.Parameters.FullBytes)
		if err != nil {
			return nil, ge.Pin(err)
		}

		return gost3410.NewPrivateKey(curve, privateKeyRaw)
	default:
		return nil, ge.Pin(&ge.UndefinedSwitchCaseError{
			Var: algo,
		})
	}
}

func DecodePEM(pemData []byte) (key *gost3410.PrivateKey, err error) {
	allow := []string{containers.PrivateKey}

	der, _ := pem.Decode(pemData)
	if der == nil || !inslice.String(der.Type, &allow) {
		return nil, ge.Pin(&ge.MismatchError{
			ComparedItems: "der.Type",
			Expected:      allow,
			Actual:        der.Type,
		})
	}

	return DecodeDER(der.Bytes)
}

func DecodePEMFile(file string) (key *gost3410.PrivateKey, err error) {
	txtFile := fico.TxtFile(file)

	pem, err := txtFile.ReadBytes()
	if err != nil {
		return nil, ge.Pin(err)
	}

	return DecodePEM(pem)
}
