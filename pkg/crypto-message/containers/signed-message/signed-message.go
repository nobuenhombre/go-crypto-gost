// Go Cryptographic Message Syntax (CMS) Signature validation library
// with GOST-R cryptographic functions support
// Copyright (C) 2019 Dmitry Dulesov <dmitry.dulesov(at)gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package signedMessage

import (
	"bytes"
	"math/big"
	"time"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	signedData "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data"
	signerInfo "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/signer-info"
	unsignedData "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/unsigned-data"

	"github.com/nobuenhombre/suikat/pkg/ge"
)

type CryptographicMessage interface {
	GetCertificateSerialNumber() *big.Int
	IsValidOnDate(date time.Time) bool
	FindCertificateSigner(caList []*certificate.Container) (*certificate.Container, error)
	//Verify(content []byte, notBefore, notAfter time.Time) error
	GetEncryptedDigest() []byte
	EncodeToDER() ([]byte, error)
	EncodeToPEM() ([]byte, error)
}

// Container represent Cryptographic Message Syntax (CMS)
// with Signed-data Content Type - RFC5652
type Container struct {
	Certificates []*certificate.Container
	Content      *unsignedData.Container
	SignedData   *signedData.Container
}

func (cms *Container) GetEncryptedDigest() []byte {
	return cms.SignedData.SignerInfos[0].EncryptedDigest
}

// GetCertificateSerialNumber - returns Signer first Certificate serial number.
func (cms *Container) GetCertificateSerialNumber() *big.Int {
	if len(cms.Certificates) == 0 {
		return nil
	}

	return cms.Certificates[0].TBSCertificate.SerialNumber
}

// getCertificateByIssuerAndSerial find certificate by Issuer byte sequence and Serial number
func (cms *Container) getCertificateByIssuerAndSerial(ias signerInfo.IssuerAndSerial) *certificate.Container {
	for _, cert := range cms.Certificates {
		isSerialMatch := cert.TBSCertificate.SerialNumber.Cmp(ias.SerialNumber) == 0
		isIssuerMatch := bytes.Compare(cert.TBSCertificate.Issuer.FullBytes, ias.IssuerName.FullBytes) == 0

		if isSerialMatch && isIssuerMatch {
			return cert
		}
	}

	return nil
}

func (cms *Container) IsValidOnDate(date time.Time) bool {
	for _, cert := range cms.Certificates {
		isValid := cert.IsValidOnDate(date)
		if !isValid {
			return false
		}
	}

	return true
}

// FindCertificateSigner find certificate signer
func (cms *Container) FindCertificateSigner(caList []*certificate.Container) (*certificate.Container, error) {
	var signerCertificate *certificate.Container

	signerCertificate = nil
	for _, cert := range cms.Certificates {
		for _, caCert := range caList {
			if certificate.IsCertificatesEqual(cert, caCert) {
				signerCertificate = caCert

				break
			}
		}

		if signerCertificate != nil {
			break
		}
	}

	if signerCertificate == nil {
		return nil, ge.Pin(&ge.NotFoundError{Key: "0 matched"})
	}

	return signerCertificate, nil
}

// Verify - CMS Validity.
// check equality CMS content and provided value @content
// check signing time in the range between notBefore-notAfter
// check content digest
// check content signature over provided signer certificates
//func (cms *CMS) Verify(content []byte, notBefore, notAfter time.Time) error {
//	if len(cms.SignedData.SignerInfos) != 1 {
//		return ge.Pin(&ge.MismatchError{
//			ComparedItems: "len(cms.SignedData.SignerInfos)",
//			Expected:      1,
//			Actual:        len(cms.SignedData.SignerInfos),
//		})
//	}
//
//	if content != nil && bytes.Compare(*cms.Content, content) != 0 {
//		return ge.Pin(&ge.MismatchError{
//			ComparedItems: "*cms.Content vs content",
//			Expected:      *cms.Content,
//			Actual:        content,
//		})
//	}
//
//	var (
//		signingTime time.Time
//		digest      []byte
//		val         asn1.RawValue
//	)
//
//	for _, signer := range cms.SignedData.SignerInfos {
//		// var hashType = hashOid.UnknownHashFunction
//
//		signerCertificate := cms.getCertificateByIssuerAndSerial(signer.IssuerAndSerialNumber)
//		if signerCertificate == nil {
//			return ge.New("signerCertificate is nil")
//		}
//
//		//get Content digest and signing time from SignedAttributes
//
//		for _, attr := range signer.AuthenticatedAttributes {
//			if attr.Value.Bytes != nil {
//				_, err := asn1.Unmarshal(signer.AuthenticatedAttributes.Raw, &val)
//				if err != nil {
//					return ge.Pin(err)
//				}
//
//				asn1Data := val.Bytes
//
//				for len(asn1Data) > 0 {
//					var attr signerInfo.Attribute
//
//					asn1Data, err = asn1.Unmarshal(asn1Data, &attr)
//					if err != nil {
//						return ge.Pin(err)
//					}
//
//					signingTimeOid, err := oids.Get(oids.AttributeSigningTime)
//					if err != nil {
//						return ge.Pin(err)
//					}
//
//					if attr.Type.Equal(signingTimeOid) {
//						_, err = asn1.Unmarshal(attr.Value.Bytes, &signingTime)
//						if err != nil {
//							return ge.Pin(err)
//						}
//					}
//
//					attributeMessageDigestOid, err := oids.Get(oids.AttributeMessageDigest)
//					if err != nil {
//						return ge.Pin(err)
//					}
//					if attr.Type.Equal(attributeMessageDigestOid) {
//						_, err = asn1.Unmarshal(attr.Value.Bytes, &digest)
//						if err != nil {
//							return ge.Pin(err)
//						}
//					}
//				}
//
//				//log.Printf("signing time %v", signingTime)
//				if notBefore.After(signingTime) || notAfter.Before(signingTime) {
//					return ge.New("wrong signing time")
//				}
//
//				signer.AuthenticatedAttributes.Raw[0] = asn1.TagSet | 0x20 //!hack. replace implicit tag with SET(17)+Compound(32)
//			}
//		}
//
//		digestOidId, err := oids.GetID(signer.DigestAlgorithm.Algorithm)
//		if err != nil {
//			return ge.Pin(err)
//		}
//
//		digestHashFunc, err := hashOid.Get(digestOidId)
//		if err != nil {
//			return ge.Pin(err)
//		}
//
//		if !digestHashFunc.IsActual() {
//			return ge.Pin(&algorithm.UnsupportedAlgorithmError{})
//		}
//
//		//h := hashType.New()
//		//
//		//h.Write(cms.Content)
//		//computed := h.Sum(nil)
//		//
//		//if bytes.Compare(computed, digest) != 0 {
//		//	return ge.Pin(&SignatureVerifyError{})
//		//}
//
//		// HACK!!!
//		// openssl use digestAlgorithm  hash functions in all cases
//		// verify RFC https://tools.ietf.org/html/rfc5652
//
//		digestEncriptionOidId, err := oids.GetID(signer.DigestEncryptionAlgorithm.Algorithm)
//		if err != nil {
//			return ge.Pin(err)
//		}
//
//		digestEncriptionAlgorithm, err := algorithm.GetSignatureAlgorithm(digestEncriptionOidId)
//		if err != nil {
//			return ge.Pin(err)
//		}
//
//		if digestEncriptionAlgorithm == nil {
//			//if signer.DigestEncryptionAlgorithm.Algorithm.Equal(oidPublicKeyRSA) {
//			//	for _, item := range signatureAlgorithmDetails {
//			//		if item.hash == hashType && item.pubKeyAlgo == RSA {
//			//			algo = &item
//			//			break
//			//		}
//			//	}
//			//}
//			//
//			//if algo == nil {
//			return ge.Pin(&algorithm.UnsupportedAlgorithmError{})
//			//}
//		}
//
//		if digestEncriptionAlgorithm.Hash == hashOid.UnknownHashFunction {
//			digestEncriptionAlgorithm.Hash = digestHashFunc
//		}
//
//		err = signerCertificate.CheckSignature(
//			digestEncriptionAlgorithm,
//			signer.AuthenticatedAttributes.Raw[:],
//			signer.EncryptedDigest[:],
//		)
//		if err != nil {
//			return ge.Pin(err)
//		}
//	}
//
//	return nil
//}

//func BytesEqual(a, b []byte) bool {
//	if len(a) != len(b) {
//		return false
//	}
//
//	for key := range a {
//		if a[key] != b[key] {
//			return false
//		}
//	}
//
//	return true
//}
//
