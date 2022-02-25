package sign

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	signeddata "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data"

	// nolint[:lll]
	contentinfo "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/content-info"
	// nolint[:lll]
	rawcertificates "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/raw-certificates"
	// nolint[:lll]
	signerinfo "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/signer-info"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	hashOid "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/hash"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/chunks"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

// SignedData is an opaque data structure for creating signed data payloads
type SignedData struct {
	sd                  signeddata.Container
	certs               []*certificate.Container
	data, messageDigest []byte
	digestOid           asn1.ObjectIdentifier
	encryptionOid       asn1.ObjectIdentifier
}

// NewSignedData takes data and initializes a PKCS7 SignedData struct that is
// ready to be signed via AddSigner. The digest algorithm is set to SHA1 by default
// and can be changed by calling SetDigestAlgorithm.
func NewSignedData(data []byte) (*SignedData, error) {
	content, err := asn1.Marshal(data)
	if err != nil {
		return nil, ge.Pin(err)
	}

	oidData, err := oids.Get(oids.Data)
	if err != nil {
		return nil, ge.Pin(err)
	}

	ci := contentinfo.Container{
		ContentType: oidData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: content, IsCompound: true},
	}

	sd := signeddata.Container{
		ContentInfo: ci,
		Version:     1,
	}

	oidDigestAlgorithm, err := oids.Get(oids.Tc26Gost34112012256)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return &SignedData{sd: sd, data: data, digestOid: oidDigestAlgorithm}, nil
}

// SignerInfoConfig are optional values to include when adding a signer
type SignerInfoConfig struct {
	ExtraSignedAttributes   []Attribute
	ExtraUnsignedAttributes []Attribute
}

// Attribute represents a key value pair attribute. Value must be marshalable byte
// `encoding/asn1`
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}

// SetDigestAlgorithm sets the digest algorithm to be used in the signing process.
//
// This should be called before adding signers
func (sd *SignedData) SetDigestAlgorithm(d asn1.ObjectIdentifier) {
	sd.digestOid = d
}

// SetEncryptionAlgorithm sets the encryption algorithm to be used in the signing process.
//
// This should be called before adding signers
func (sd *SignedData) SetEncryptionAlgorithm(d asn1.ObjectIdentifier) {
	sd.encryptionOid = d
}

// AddSigner is a wrapper around AddSignerChain() that adds a signer without any parent.
func (sd *SignedData) AddSigner(ee *certificate.Container, pkey *gost3410.PrivateKey, config SignerInfoConfig) error {
	var parents []*certificate.Container

	return sd.AddSignerChain(ee, pkey, parents, config)
}

// AddSignerChain signs attributes about the content and adds certificates
// and signers infos to the Signed Data. The certificate and private key
// of the end-entity signer are used to issue the signature, and any
// parent of that end-entity that need to be added to the list of
// certifications can be specified in the parents slice.
//
// The signature algorithm used to hash the data is the one of the end-entity
// certificate.
func (sd *SignedData) AddSignerChain(
	ee *certificate.Container,
	pkey *gost3410.PrivateKey,
	parents []*certificate.Container,
	config SignerInfoConfig,
) error {
	// Following RFC 2315, 9.2 SignerInfo type, the distinguished name of
	// the issuer of the end-entity signer is stored in the issuerAndSerialNumber
	// section of the SignedData.SignerInfo, alongside the serial number of
	// the end-entity.
	var ias signerinfo.IssuerAndSerial
	ias.SerialNumber = ee.TBSCertificate.SerialNumber

	if len(parents) == 0 {
		// no parent, the issuer is the end-entity cert itself
		ias.IssuerName = asn1.RawValue{FullBytes: ee.TBSCertificate.Issuer.FullBytes} // RawIssuer
	} else {
		err := certificate.VerifyPartialChain(ee, parents)
		if err != nil {
			return ge.Pin(err)
		}

		// the first parent is the issuer
		ias.IssuerName = asn1.RawValue{FullBytes: parents[0].TBSCertificate.Subject.FullBytes} // RawSubject
	}

	sd.sd.DigestAlgorithmIdentifiers = append(sd.sd.DigestAlgorithmIdentifiers,
		pkix.AlgorithmIdentifier{Algorithm: sd.digestOid},
	)

	digestOidID, err := oids.GetID(sd.digestOid)
	if err != nil {
		return ge.Pin(err)
	}

	digestFunc, err := hashOid.Get(digestOidID)
	if err != nil {
		return ge.Pin(err)
	}

	hash := digestFunc

	h := hash.New()
	h.Write(sd.data)
	sd.messageDigest = chunks.ReverseFullBytes(h.Sum(nil))

	encryptionOid, err := oids.Get(digestOidID)
	if err != nil {
		return ge.Pin(err)
	}

	oidAttributeContentType, err := oids.Get(oids.AttributeContentType)
	if err != nil {
		return err
	}

	oidAttributeMessageDigest, err := oids.Get(oids.AttributeMessageDigest)
	if err != nil {
		return err
	}

	oidAttributeSigningTime, err := oids.Get(oids.AttributeSigningTime)
	if err != nil {
		return err
	}

	attrs := &signerinfo.Attributes{}
	attrs.Add(oidAttributeContentType, sd.sd.ContentInfo.ContentType)
	attrs.Add(oidAttributeMessageDigest, sd.messageDigest)
	attrs.Add(oidAttributeSigningTime, time.Now().UTC())

	for _, attr := range config.ExtraSignedAttributes {
		attrs.Add(attr.Type, attr.Value)
	}

	finalAttrs, err := attrs.ForMarshalling()
	if err != nil {
		return err
	}

	unsignedAttrs := &signerinfo.Attributes{}
	for _, attr := range config.ExtraUnsignedAttributes {
		unsignedAttrs.Add(attr.Type, attr.Value)
	}

	finalUnsignedAttrs, err := unsignedAttrs.ForMarshalling()
	if err != nil {
		return err
	}

	// create signature of signed attributes
	signature, err := sd.SignAttributes(finalAttrs, pkey, hash)
	if err != nil {
		return err
	}

	signer := signerinfo.Container{
		AuthenticatedAttributes:   finalAttrs,
		UnauthenticatedAttributes: finalUnsignedAttrs,
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: sd.digestOid},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: encryptionOid},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           signature,
		Version:                   1,
	}

	sd.certs = append(sd.certs, ee)
	if len(parents) > 0 {
		sd.certs = append(sd.certs, parents...)
	}

	sd.sd.SignerInfos = append(sd.sd.SignerInfos, signer)

	return nil
}

// SignAttributes signs the DER encoded form of the attributes with the private key
func (sd *SignedData) SignAttributes(
	attrs []signerinfo.Attribute,
	key *gost3410.PrivateKey,
	digestAlg hashOid.Function,
) ([]byte, error) {
	attrBytes, err := signerinfo.EncodeAttributeSliceToDER(attrs)
	if err != nil {
		return nil, err
	}

	h := digestAlg.New()
	h.Write(attrBytes)
	hash := h.Sum(nil)

	return key.Sign(rand.Reader, hash, nil)
}

// SignWithoutAttr issues a signature on the content of the pkcs7 SignedData.
// Unlike AddSigner/AddSignerChain, it calculates the digest on the data alone
// and does not include any signed attributes like timestamp and so on.
//
// This function is needed to sign old Android APKs, something you probably
// shouldn't do unless you're maintaining backward compatibility for old
// applications.
func (sd *SignedData) SignWithoutAttr(
	ee *certificate.Container,
	pkey *gost3410.PrivateKey,
	config SignerInfoConfig,
) error {
	var signature []byte

	sd.sd.DigestAlgorithmIdentifiers = append(
		sd.sd.DigestAlgorithmIdentifiers,
		pkix.AlgorithmIdentifier{Algorithm: sd.digestOid},
	)

	hashOidID, err := oids.GetID(sd.digestOid)
	if err != nil {
		return ge.Pin(err)
	}

	hash, err := hashOid.Get(hashOidID)
	if err != nil {
		return ge.Pin(err)
	}

	h := hash.New()
	h.Write(sd.data)
	sd.messageDigest = chunks.ReverseFullBytes(h.Sum(nil))

	signature, err = pkey.Sign(rand.Reader, sd.messageDigest, nil)
	if err != nil {
		return ge.Pin(err)
	}

	var ias signerinfo.IssuerAndSerial
	ias.SerialNumber = ee.TBSCertificate.SerialNumber
	// no parent, the issue is the end-entity cert itself
	ias.IssuerName = asn1.RawValue{FullBytes: ee.TBSCertificate.Issuer.FullBytes} // RawIssuer

	if sd.encryptionOid == nil {
		// if the encryption algorithm wasn't set by SetEncryptionAlgorithm,
		// infer it from the digest algorithm
		sd.encryptionOid, err = oids.Get(hashOidID)
		if err != nil {
			return ge.Pin(err)
		}
	}

	signer := signerinfo.Container{
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: sd.digestOid},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sd.encryptionOid},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           signature,
		Version:                   1,
	}

	// create signature of signed attributes
	sd.certs = append(sd.certs, ee)
	sd.sd.SignerInfos = append(sd.sd.SignerInfos, signer)

	return nil
}

// AddCertificate adds the certificate to the payload. Useful for parent certificates
func (sd *SignedData) AddCertificate(cert *certificate.Container) {
	sd.certs = append(sd.certs, cert)
}

// Detach removes content from the signed data struct to make it a detached signature.
// This must be called right before Finish()
func (sd *SignedData) Detach() error {
	oidData, err := oids.Get(oids.Data)
	if err != nil {
		return ge.Pin(err)
	}

	sd.sd.ContentInfo = contentinfo.Container{ContentType: oidData}

	return nil
}

// GetSignedData returns the private Signed Data
func (sd *SignedData) GetSignedData() *signeddata.Container {
	return &sd.sd
}

// Finish marshals the content and its signers
func (sd *SignedData) Finish() ([]byte, error) {
	rawCertificates, err := rawcertificates.DecodeCertificatesContainer(sd.certs)
	if err != nil {
		return nil, ge.Pin(err)
	}

	sd.sd.RawCertificates = *rawCertificates

	inner, err := asn1.Marshal(sd.sd)
	if err != nil {
		return nil, ge.Pin(err)
	}

	oidSignedData, err := oids.Get(oids.SignedData)
	if err != nil {
		return nil, ge.Pin(err)
	}

	outer := contentinfo.Container{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: inner, IsCompound: true},
	}

	return asn1.Marshal(outer)
}

// RemoveAuthenticatedAttributes removes authenticated attributes from signedData
// similar to OpenSSL's PKCS7_NOATTR or -noattr flags
func (sd *SignedData) RemoveAuthenticatedAttributes() {
	for i := range sd.sd.SignerInfos {
		sd.sd.SignerInfos[i].AuthenticatedAttributes = nil
	}
}

// RemoveUnauthenticatedAttributes removes unauthenticated attributes from signedData
func (sd *SignedData) RemoveUnauthenticatedAttributes() {
	for i := range sd.sd.SignerInfos {
		sd.sd.SignerInfos[i].UnauthenticatedAttributes = nil
	}
}
