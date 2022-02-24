package pkcs7gost

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"

	pemFormat "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	signedData "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data"
	contentInfo "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/content-info"
	rawCertificates "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/raw-certificates"
	signerInfo "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/signer-info"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	hashOid "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/hash"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/chunks"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

// SignedData is an opaque data structure for creating signed data payloads
type SignedData struct {
	sd                  signedData.SignedData
	certs               []*certificate.Certificate
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

	ci := contentInfo.ContentInfo{
		ContentType: oidData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
	}

	sd := signedData.SignedData{
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

func marshalAttributes(attrs []signerInfo.Attribute) ([]byte, error) {
	encodedAttributes, err := asn1.Marshal(struct {
		A []signerInfo.Attribute `asn1:"set"`
	}{A: attrs})
	if err != nil {
		return nil, ge.Pin(err)
	}

	// Remove the leading sequence octets
	var raw asn1.RawValue
	asn1.Unmarshal(encodedAttributes, &raw)

	return raw.Bytes, nil
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
func (sd *SignedData) AddSigner(ee *certificate.Certificate, pkey *gost3410.PrivateKey, config SignerInfoConfig) error {
	var parents []*certificate.Certificate
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
func (sd *SignedData) AddSignerChain(ee *certificate.Certificate, pkey *gost3410.PrivateKey, parents []*certificate.Certificate, config SignerInfoConfig) error {
	// Following RFC 2315, 9.2 SignerInfo type, the distinguished name of
	// the issuer of the end-entity signer is stored in the issuerAndSerialNumber
	// section of the SignedData.SignerInfo, alongside the serial number of
	// the end-entity.
	var ias signerInfo.IssuerAndSerial
	ias.SerialNumber = ee.TBSCertificate.SerialNumber

	if len(parents) == 0 {
		// no parent, the issuer is the end-entity cert itself
		ias.IssuerName = asn1.RawValue{FullBytes: ee.TBSCertificate.Issuer.FullBytes} // RawIssuer
	} else {
		err := verifyPartialChain(ee, parents)
		if err != nil {
			return ge.Pin(err)
		}

		// the first parent is the issuer
		ias.IssuerName = asn1.RawValue{FullBytes: parents[0].TBSCertificate.Subject.FullBytes} // RawSubject
	}

	sd.sd.DigestAlgorithmIdentifiers = append(sd.sd.DigestAlgorithmIdentifiers,
		pkix.AlgorithmIdentifier{Algorithm: sd.digestOid},
	)

	digestOidId, err := oids.GetID(sd.digestOid)
	if err != nil {
		return ge.Pin(err)
	}

	digestFunc, err := hashOid.Get(digestOidId)
	if err != nil {
		return ge.Pin(err)
	}

	hash := digestFunc

	h := hash.New()
	h.Write(sd.data)
	sd.messageDigest = h.Sum(nil)

	encryptionOid, err := oids.Get(digestOidId)
	if err != nil {
		return ge.Pin(err)
	}

	//oidAttributeContentType, err := oids.Get(oids.AttributeContentType)
	//if err != nil {
	//	return err
	//}
	//
	//oidAttributeMessageDigest, err := oids.Get(oids.AttributeMessageDigest)
	//if err != nil {
	//	return err
	//}
	//
	//oidAttributeSigningTime, err := oids.Get(oids.AttributeSigningTime)
	//if err != nil {
	//	return err
	//}

	//attrs := &signerInfo.Attributes{}
	//attrs.Add(oidAttributeContentType, sd.sd.ContentInfo.ContentType)
	//attrs.Add(oidAttributeMessageDigest, sd.messageDigest)
	//attrs.Add(oidAttributeSigningTime, time.Now().UTC())
	//
	//for _, attr := range config.ExtraSignedAttributes {
	//	attrs.Add(attr.Type, attr.Value)
	//}

	//finalAttrs, err := attrs.ForMarshalling()
	//if err != nil {
	//	return err
	//}

	//unsignedAttrs := &signerInfo.Attributes{}
	//for _, attr := range config.ExtraUnsignedAttributes {
	//	unsignedAttrs.Add(attr.Type, attr.Value)
	//}

	//finalUnsignedAttrs, err := unsignedAttrs.ForMarshalling()
	//if err != nil {
	//	return err
	//}

	// create signature of signed attributes
	//signature, err := signAttributes(finalAttrs, pkey, hash)
	//if err != nil {
	//	return err
	//}

	signature, err := signRevertedDigest(sd.messageDigest, pkey, hash)
	if err != nil {
		return ge.Pin(err)
	}

	signer := signerInfo.SignerInfo{
		AuthenticatedAttributes:   nil, //finalAttrs,
		UnauthenticatedAttributes: nil, //finalUnsignedAttrs,
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

// SignWithoutAttr issues a signature on the content of the pkcs7 SignedData.
// Unlike AddSigner/AddSignerChain, it calculates the digest on the data alone
// and does not include any signed attributes like timestamp and so on.
//
// This function is needed to sign old Android APKs, something you probably
// shouldn't do unless you're maintaining backward compatibility for old
// applications.
func (sd *SignedData) SignWithoutAttr(ee *certificate.Certificate, pkey *gost3410.PrivateKey, config SignerInfoConfig) error {
	var signature []byte
	sd.sd.DigestAlgorithmIdentifiers = append(sd.sd.DigestAlgorithmIdentifiers, pkix.AlgorithmIdentifier{Algorithm: sd.digestOid})

	hashOidId, err := oids.GetID(sd.digestOid)
	if err != nil {
		return ge.Pin(err)
	}

	hash, err := hashOid.Get(hashOidId)
	if err != nil {
		return ge.Pin(err)
	}

	h := hash.New()
	h.Write(sd.data)
	sd.messageDigest = h.Sum(nil)

	signature, err = pkey.Sign(rand.Reader, sd.messageDigest, nil)
	if err != nil {
		return ge.Pin(err)
	}

	var ias signerInfo.IssuerAndSerial
	ias.SerialNumber = ee.TBSCertificate.SerialNumber
	// no parent, the issue is the end-entity cert itself
	ias.IssuerName = asn1.RawValue{FullBytes: ee.TBSCertificate.Issuer.FullBytes} // RawIssuer

	if sd.encryptionOid == nil {
		// if the encryption algorithm wasn't set by SetEncryptionAlgorithm,
		// infer it from the digest algorithm
		sd.encryptionOid, err = oids.Get(hashOidId)
		if err != nil {
			return ge.Pin(err)
		}
	}

	signer := signerInfo.SignerInfo{
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
func (sd *SignedData) AddCertificate(cert *certificate.Certificate) {
	sd.certs = append(sd.certs, cert)
}

// Detach removes content from the signed data struct to make it a detached signature.
// This must be called right before Finish()
func (sd *SignedData) Detach() error {
	oidData, err := oids.Get(oids.Data)
	if err != nil {
		return ge.Pin(err)
	}

	sd.sd.ContentInfo = contentInfo.ContentInfo{ContentType: oidData}

	return nil
}

// GetSignedData returns the private Signed Data
func (sd *SignedData) GetSignedData() *signedData.SignedData {
	return &sd.sd
}

// Finish marshals the content and its signers
func (sd *SignedData) Finish() ([]byte, error) {
	sd.sd.RawCertificates = marshalCertificates(sd.certs)

	inner, err := asn1.Marshal(sd.sd)
	if err != nil {
		return nil, ge.Pin(err)
	}

	oidSignedData, err := oids.Get(oids.SignedData)
	if err != nil {
		return nil, ge.Pin(err)
	}

	outer := contentInfo.ContentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
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

// verifyPartialChain checks that a given cert is issued by the first parent in the list,
// then continue down the path. It doesn't require the last parent to be a root CA,
// or to be trusted in any truststore. It simply verifies that the chain provided, albeit
// partial, makes sense.
func verifyPartialChain(cert *certificate.Certificate, parents []*certificate.Certificate) error {
	//var x x509.Certificate
	if len(parents) == 0 {
		return ge.New("pkcs7: zero parents provided to verify the signature of certificate") // %q , cert.Subject.CommonName)
	}

	err := cert.CheckSignatureFrom(parents[0])
	if err != nil {
		return ge.Pin(err)
	}

	if len(parents) == 1 {
		// there is no more parent to check, return
		return nil
	}

	return verifyPartialChain(parents[0], parents[1:])
}

// signs the DER encoded form of the attributes with the private key
func signAttributes(attrs []signerInfo.Attribute, key *gost3410.PrivateKey, digestAlg hashOid.Function) ([]byte, error) {
	attrBytes, err := marshalAttributes(attrs)
	if err != nil {
		return nil, err
	}

	h := digestAlg.New()
	h.Write(attrBytes)
	hash := h.Sum(nil)

	return key.Sign(rand.Reader, hash, nil)
}

func signRevertedDigest(digest []byte, key *gost3410.PrivateKey, digestAlg hashOid.Function) ([]byte, error) {
	revertedDigest := chunks.ReverseFullBytes(digest)

	//h := digestAlg.New()
	//h.Write(revertedDigest)
	//hash := h.Sum(nil)

	return key.Sign(rand.Reader, revertedDigest, nil)
}

// concats and wraps the certificates in the RawValue structure
func marshalCertificates(certs []*certificate.Certificate) rawCertificates.RawCertificates {
	var buf bytes.Buffer

	for _, cert := range certs {
		buf.Write(cert.Raw)
	}

	rawCerts, _ := marshalCertificateBytes(buf.Bytes())

	return rawCerts
}

// Even though, the tag & length are stripped out during marshalling the
// RawContent, we have to encode it into the RawContent. If its missing,
// then `asn1.Marshal()` will strip out the certificate wrapper instead.
func marshalCertificateBytes(certs []byte) (rawCertificates.RawCertificates, error) {
	var val = asn1.RawValue{Bytes: certs, Class: 2, Tag: 0, IsCompound: true}

	b, err := asn1.Marshal(val)
	if err != nil {
		return rawCertificates.RawCertificates{}, ge.Pin(err)
	}

	return rawCertificates.RawCertificates{Raw: b}, nil
}

func SignAndDetach(content []byte, cert *certificate.Certificate, privateKey *gost3410.PrivateKey) (signed []byte, err error) {
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		return nil, ge.Pin(err)
	}

	if err = toBeSigned.AddSigner(cert, privateKey, SignerInfoConfig{}); err != nil {
		return nil, ge.Pin(err)
	}

	// Detach signature, omit if you want an embedded signature
	toBeSigned.Detach()

	signed, err = toBeSigned.Finish()
	if err != nil {
		return nil, ge.Pin(err)
	}

	var buffer bytes.Buffer

	err = pem.Encode(&buffer, &pem.Block{Type: pemFormat.Default, Bytes: signed})
	if err != nil {
		return nil, ge.Pin(err)
	}

	return buffer.Bytes(), nil

	//p7, err := pkcs7gost.Parse(signed)
	//if err != nil {
	//	err = fmt.Errorf("Cannot parse our signed data: %s", err)
	//	return
	//}
	//
	//// since the signature was detached, reattach the content here
	//p7.Content = content
	//
	//if bytes.Compare(content, p7.Content) != 0 {
	//	err = fmt.Errorf("Our content was not in the parsed data:\n\tExpected: %s\n\tActual: %s", content, p7.Content)
	//	return
	//}
	//if err = p7.Verify(); err != nil {
	//	err = fmt.Errorf("Cannot verify our signed data: %s", err)
	//	return
	//}

	//return signed, nil
}
