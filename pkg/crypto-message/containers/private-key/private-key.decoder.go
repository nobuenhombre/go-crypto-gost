package privateKey

import (
	"encoding/asn1"
	"encoding/pem"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/curves"
	pemFormat "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/pem-format"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/fico"
	"github.com/nobuenhombre/suikat/pkg/ge"
	"github.com/nobuenhombre/suikat/pkg/inslice"
	"golang.org/x/crypto/cryptobyte"
	cryptobyteAsn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func NewPrivateKeyFromDER(derData []byte) (key *gost3410.PrivateKey, err error) {
	var privateKey PKCS8

	if _, err := asn1.Unmarshal(derData, &privateKey); err != nil {
		return nil, ge.Pin(err)
	}

	oidId, err := oids.GetID(privateKey.Algorithm.Algorithm)
	if err != nil {
		return nil, ge.Pin(err)
	}

	algo, err := algorithm.GetPublicKeyAlgorithm(oidId)
	if err != nil {
		return nil, ge.Pin(err)
	}

	switch algo {
	case algorithm.GostR34102001, algorithm.GostR34102012256, algorithm.GostR34102012512:
		var privateKeyRaw []byte

		if len(privateKey.PrivateKey) == 34 {
			s := cryptobyte.String(privateKey.PrivateKey)
			if !s.ReadASN1Bytes(&privateKeyRaw, cryptobyteAsn1.OCTET_STRING) {
				return nil, ge.New("x509: can not decode GOST public key")
			}
		} else {
			privateKeyRaw = privateKey.PrivateKey
		}

		curve, err := curves.NewCurveFromDER(privateKey.Algorithm.Parameters.FullBytes)
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

func NewPrivateKeyFromPEM(pemData []byte) (key *gost3410.PrivateKey, err error) {
	allow := []string{pemFormat.PrivateKey}

	der, _ := pem.Decode(pemData)
	if der == nil || !inslice.String(der.Type, &allow) {
		return nil, ge.Pin(&ge.MismatchError{
			ComparedItems: "der.Type",
			Expected:      allow,
			Actual:        der.Type,
		})
	}

	return NewPrivateKeyFromDER(der.Bytes)
}

func NewPrivateKeyFromFile(file string) (key *gost3410.PrivateKey, err error) {
	txtFile := fico.TxtFile(file)
	pem, err := txtFile.ReadBytes()
	if err != nil {
		return nil, ge.Pin(err)
	}

	return NewPrivateKeyFromPEM(pem)
}
