package signerinfo

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// IssuerAndSerial asn.1 Signature issuer
type IssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

// Container asn.1 CMS  struct
// RFC5652
type Container struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     IssuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []Attribute `asn1:"optional,omitempty,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []Attribute `asn1:"optional,tag:1"`
}

func (si *Container) SetUnauthenticatedAttributes(extraUnsignedAttrs []Attribute) error {
	unsignedAttrs := &Attributes{}

	for _, attr := range extraUnsignedAttrs {
		unsignedAttrs.Add(attr.Type, attr.Value)
	}

	finalUnsignedAttrs, err := unsignedAttrs.ForMarshalling()
	if err != nil {
		return err
	}

	si.UnauthenticatedAttributes = finalUnsignedAttrs

	return nil
}
