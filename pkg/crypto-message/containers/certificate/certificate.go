// Package certificate provides
// en: structure of the Container representation in the asn.1, methods for this structure
//     and the decoding function from DER
// ru: структуру представления Container в asn.1, методы для этой структуры
//     и функцию декодирования из DER
//
// asn.1 - Abstract Syntax Notation One (ASN. 1) is a standard interface description language
// for defining data structures that can be serialized and deserialized in a cross-platform way.
// It is broadly used in telecommunications and computer networking, and especially in cryptography.
// https://en.wikipedia.org/wiki/ASN.1
package certificate

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"

	publicKeyAlgorithm "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm/public-key-algorithm"
	signatureAlgorithm "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm/signature-algorithm"

	tbsCertificate "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate/tbs-certificate"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

type Service interface {
	CheckSignature(algo *signatureAlgorithm.SignatureAlgorithm, signedSource, signature []byte) (err error)
	CheckSignatureFrom(parent *Container) error
	IsValidOnDate(date time.Time) bool
	EncodeToDER() ([]byte, error)
	EncodeToPEM() ([]byte, error)
	GetSource() *Container
}

type Container struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate.Container
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// CheckSignature - Verifies signature over certificate public key
func (c *Container) CheckSignature(algo *signatureAlgorithm.SignatureAlgorithm, signedSource, signature []byte) (err error) {
	var pubKey []byte

	if algo == nil {
		return ge.New("empty algorithm")
	}

	if algo.PublicKeyAlgorithm == publicKeyAlgorithm.RSA {
		pubKey = c.TBSCertificate.PublicKeyInfo.PublicKey.RightAlign()
	} else {
		var v asn1.RawValue

		if _, err = asn1.Unmarshal(c.TBSCertificate.PublicKeyInfo.PublicKey.Bytes, &v); err != nil {
			return ge.Pin(err)
		}

		pubKey = v.Bytes
	}

	return checkSignature(algo, signedSource, signature, pubKey)
}

// CheckSignatureFrom verifies that the signature on c is a valid signature
// from parent.
func (c *Container) CheckSignatureFrom(parent *Container) error {
	if parent == nil {
		return nil
	}

	if !IsCertificatesEqual(c, parent) {
		return ge.Pin(&ge.MismatchError{
			ComparedItems: "c, parent",
			Expected:      c,
			Actual:        parent,
		})
	}

	oidId, err := oids.GetID(c.TBSCertificate.SignatureAlgorithm.Algorithm)
	if err != nil {
		return ge.Pin(err)
	}

	algo, err := signatureAlgorithm.Get(oidId)
	if err != nil {
		return ge.Pin(err)
	}

	return parent.CheckSignature(algo, c.TBSCertificate.Raw, c.SignatureValue.RightAlign())
}

func (c *Container) IsValidOnDate(date time.Time) bool {
	isAfter := date.After(c.TBSCertificate.Validity.NotAfter)
	isBefore := date.Before(c.TBSCertificate.Validity.NotBefore)

	if isBefore || isAfter {
		return false
	}

	return true
}

func (c *Container) GetSource() *Container {
	return c
}
