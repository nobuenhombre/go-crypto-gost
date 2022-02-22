package publicKeyInfo

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/curves"
	hashOid "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/hash"
	pemFormat "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/pem-format"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/ge"
	"golang.org/x/crypto/cryptobyte"
	cryptobyteAsn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// PublicKeyInfo - asn.1 Certificate PublicKey structure
// RFC5280
type PublicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type algorithmParam struct {
	Curve  asn1.ObjectIdentifier
	Digest asn1.ObjectIdentifier
}

func (pki *PublicKeyInfo) GetAlgorithm() (algorithm.PublicKeyAlgorithm, error) {
	oidId, err := oids.GetID(pki.Algorithm.Algorithm)
	if err != nil {
		return algorithm.UnknownAlgorithm, ge.Pin(err)
	}

	algo, err := algorithm.GetPublicKeyAlgorithm(oidId)
	if err != nil {
		return algorithm.UnknownAlgorithm, ge.Pin(err)
	}

	return algo, nil
}

func (pki *PublicKeyInfo) GetHashFunction() (hashOid.Function, error) {
	var params algorithmParam

	rest, err := asn1.Unmarshal(pki.Algorithm.Parameters.FullBytes, &params)
	if err != nil {
		return hashOid.UnknownHashFunction, ge.Pin(err)
	}

	if len(rest) != 0 {
		return hashOid.UnknownHashFunction, ge.Pin(&pemFormat.TrailingDataError{})
	}

	hashOidId, err := oids.GetID(params.Digest)
	if err != nil {
		return hashOid.UnknownHashFunction, ge.Pin(err)
	}

	hashFunc, err := hashOid.Get(hashOidId)
	if err != nil {
		return hashOid.UnknownHashFunction, ge.Pin(err)
	}

	return hashFunc, nil
}

func (pki *PublicKeyInfo) GetPublicKey() (*gost3410.PublicKey, error) {
	algo, err := pki.GetAlgorithm()
	if err != nil {
		return nil, ge.Pin(err)
	}

	asn1Data := pki.PublicKey.RightAlign()

	switch algo {
	case algorithm.GostR34102001, algorithm.GostR34102012256, algorithm.GostR34102012512:
		var pubRaw []byte

		s := cryptobyte.String(asn1Data)
		if !s.ReadASN1Bytes(&pubRaw, cryptobyteAsn1.OCTET_STRING) {
			return nil, ge.New("x509: can not decode GOST public key")
		}

		curve, err := curves.NewCurveFromDER(pki.Algorithm.Parameters.FullBytes)
		if err != nil {
			return nil, ge.Pin(err)
		}

		return gost3410.NewPublicKey(curve, pubRaw)
	default:
		return nil, nil
	}
}
