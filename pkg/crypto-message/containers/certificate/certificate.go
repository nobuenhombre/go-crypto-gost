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
	CheckSignatureFrom(parent *Certificate) error
	IsValidOnDate(date time.Time) bool
	EncodeToDER() ([]byte, error)
	EncodeToPEM() ([]byte, error)
	GetSource() *Certificate
}

type Certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate.TBSCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// CheckSignature - Verifies signature over certificate public key
func (c *Certificate) CheckSignature(algo *signatureAlgorithm.SignatureAlgorithm, signedSource, signature []byte) (err error) {
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
func (c *Certificate) CheckSignatureFrom(parent *Certificate) error {
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

func (c *Certificate) IsValidOnDate(date time.Time) bool {
	isAfter := date.After(c.TBSCertificate.Validity.NotAfter)
	isBefore := date.Before(c.TBSCertificate.Validity.NotBefore)

	if isBefore || isAfter {
		return false
	}

	return true
}

func (c *Certificate) GetSource() *Certificate {
	return c
}
