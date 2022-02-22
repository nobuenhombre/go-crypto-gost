package certificate

import (
	"bytes"
	"crypto/rsa"
	"encoding/asn1"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm"
	pemFormat "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/pem-format"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/ge"
	"log"
	"math/big"
)

func IsCertificatesEqual(a, b *Certificate) bool {
	isIssuerEqual := bytes.Equal(a.TBSCertificate.Issuer.FullBytes, b.TBSCertificate.Issuer.FullBytes)
	isPublicKeyEqual := bytes.Equal(a.TBSCertificate.PublicKeyInfo.PublicKey.Bytes, b.TBSCertificate.PublicKeyInfo.PublicKey.Bytes)

	return isIssuerEqual && isPublicKeyEqual
}

// Reverse - some GOST cryptographic function accept LE (little endian) Big integer as bytes array.
// golang big.Int internal representation is BE (big endian)
// Reverse convert LE to BE and vice versa
func Reverse(d []byte) {
	for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = d[j], d[i]
	}
}

// RSA public key PKCS#1 representation
type PKCS1PublicKey struct {
	N *big.Int
	E int
}

func checkSignatureGostR34102001(signature, digest, pubKey []byte) error {
	curve := gost3410.CurveIdGostR34102001CryptoProAParamSet()

	pk, err := gost3410.NewPublicKey(curve, pubKey)
	if err != nil {
		return ge.Pin(err)
	}

	Reverse(digest)

	ok, err := pk.VerifyDigest(digest, signature[:])
	if err != nil {
		return ge.Pin(err)
	}

	if !ok {
		return ge.Pin(&VerifyDigestError{})
	}

	return nil
}

func checkSignatureGostR34102012512(signature, digest, pubKey []byte) error {
	curve := gost3410.CurveIdtc26gost341012512paramSetA()

	pk, err := gost3410.NewPublicKey(curve, pubKey)
	if err != nil {
		return ge.Pin(err)
	}

	Reverse(digest)

	ok, err := pk.VerifyDigest(digest, signature[:])
	if err != nil {
		return ge.Pin(err)
	}

	if !ok {
		return ge.Pin(&VerifyDigestError{})
	}

	return nil
}

// checkSignatureRSA - see. https://golang.org/src/crypto/x509/x509.go?s=27969:28036#L800
func checkSignatureRSA(algo *algorithm.SignatureAlgorithm, signature, digest, pubKey []byte) error {
	p := new(PKCS1PublicKey)

	rest, err := asn1.Unmarshal(pubKey, p)
	if err != nil {
		log.Print(err)
		return ge.Pin(err)
	}

	if len(rest) != 0 {
		return ge.Pin(&pemFormat.TrailingDataError{})
	}

	pub := &rsa.PublicKey{
		E: p.E,
		N: p.N,
	}

	return rsa.VerifyPKCS1v15(pub, algo.Hash.CryptoHash(), digest, signature)
}

// checkSignature - verifies signature over provided public key and digest/signature algorithm pair
// ToDo create and store PublicKey in certificate during parse state
// ToDo concern algorithm parameters for GOST cryptography . adjust PublicKey ParamSet according to them
func checkSignature(algo *algorithm.SignatureAlgorithm, signedSource, signature, pubKey []byte) error {

	if algo == nil || !algo.Hash.Actual() || !algo.PublicKeyAlgorithm.Actual() {
		return ge.Pin(&algorithm.UnsupportedAlgorithmError{})
	}

	h := algo.Hash.New()
	h.Write(signedSource)
	digest := h.Sum(nil)

	var err error

	switch algo.PublicKeyAlgorithm {
	case algorithm.GostR34102001, algorithm.GostR34102012256:
		err = checkSignatureGostR34102001(signature, digest, pubKey)
		if err != nil {
			return ge.Pin(err)
		}

	case algorithm.GostR34102012512:
		err = checkSignatureGostR34102012512(signature, digest, pubKey)
		if err != nil {
			return ge.Pin(err)
		}

	case algorithm.RSA:
		err = checkSignatureRSA(algo, signature, digest, pubKey)
		if err != nil {
			return ge.Pin(err)
		}

	default:
		return ge.Pin(&algorithm.UnsupportedAlgorithmError{})
	}

	return nil
}
