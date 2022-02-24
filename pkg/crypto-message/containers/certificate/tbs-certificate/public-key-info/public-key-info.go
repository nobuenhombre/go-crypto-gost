// Package publicKeyInfo provides
// en: structure of the public key representation in the asn.1, methods for this structure
//     and the decoding function from DER
// ru: структуру представления публичного ключа в asn.1, методы для этой структуры
//     и функцию декодирования из DER
//
// asn.1 - Abstract Syntax Notation One (ASN. 1) is a standard interface description language
// for defining data structures that can be serialized and deserialized in a cross-platform way.
// It is broadly used in telecommunications and computer networking, and especially in cryptography.
// https://en.wikipedia.org/wiki/ASN.1
package publicKeyInfo

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	publicKeyAlgorithm "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm/public-key-algorithm"

	pemFormat "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/curves"
	hashOid "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/hash"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/ge"
	"golang.org/x/crypto/cryptobyte"
	cryptobyteAsn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Container - asn.1 Certificate PublicKey structure
// RFC5280
type Container struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type algorithmParam struct {
	Curve  asn1.ObjectIdentifier
	Digest asn1.ObjectIdentifier
}

func (pki *Container) GetAlgorithm() (publicKeyAlgorithm.PublicKeyAlgorithm, error) {
	oidId, err := oids.GetID(pki.Algorithm.Algorithm)
	if err != nil {
		return publicKeyAlgorithm.UnknownAlgorithm, ge.Pin(err)
	}

	algo, err := publicKeyAlgorithm.Get(oidId)
	if err != nil {
		return publicKeyAlgorithm.UnknownAlgorithm, ge.Pin(err)
	}

	return algo, nil
}

func (pki *Container) GetHashFunction() (hashOid.Function, error) {
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

func (pki *Container) GetPublicKey() (*gost3410.PublicKey, error) {
	algo, err := pki.GetAlgorithm()
	if err != nil {
		return nil, ge.Pin(err)
	}

	asn1Data := pki.PublicKey.RightAlign()

	switch algo {
	case publicKeyAlgorithm.GostR34102001, publicKeyAlgorithm.GostR34102012256, publicKeyAlgorithm.GostR34102012512:
		var pubRaw []byte

		s := cryptobyte.String(asn1Data)
		if !s.ReadASN1Bytes(&pubRaw, cryptobyteAsn1.OCTET_STRING) {
			return nil, ge.New("x509: can not decode GOST public key")
		}

		curve, err := curves.DecodeDER(pki.Algorithm.Parameters.FullBytes)
		if err != nil {
			return nil, ge.Pin(err)
		}

		return gost3410.NewPublicKey(curve, pubRaw)
	default:
		return nil, nil
	}
}
