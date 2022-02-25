package certificate

import (
	"bytes"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"

	"github.com/nobuenhombre/suikat/pkg/chunks"

	publickeyalgorithm "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm/public-key-algorithm"
	signaturealgorithm "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm/signature-algorithm"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

func IsCertificatesEqual(a, b *Container) bool {
	isIssuerEqual := bytes.Equal(
		a.TBSCertificate.Issuer.FullBytes,
		b.TBSCertificate.Issuer.FullBytes,
	)

	isPublicKeyEqual := bytes.Equal(
		a.TBSCertificate.PublicKeyInfo.PublicKey.Bytes,
		b.TBSCertificate.PublicKeyInfo.PublicKey.Bytes,
	)

	return isIssuerEqual && isPublicKeyEqual
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

	// Reverse - some GOST cryptographic function accept LE (little endian) Big integer as bytes array.
	// golang big.Int internal representation is BE (big endian)
	// Reverse convert LE to BE and vice versa
	chunks.ReverseFullBytes(digest)

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

	// Reverse - some GOST cryptographic function accept LE (little endian) Big integer as bytes array.
	// golang big.Int internal representation is BE (big endian)
	// Reverse convert LE to BE and vice versa
	chunks.ReverseFullBytes(digest)

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
func checkSignatureRSA(algo *signaturealgorithm.SignatureAlgorithm, signature, digest, pubKey []byte) error {
	p := new(PKCS1PublicKey)

	rest, err := asn1.Unmarshal(pubKey, p)
	if err != nil {
		return ge.Pin(err)
	}

	if len(rest) != 0 {
		return ge.Pin(&containers.TrailingDataError{})
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
func checkSignature(algo *signaturealgorithm.SignatureAlgorithm, signedSource, signature, pubKey []byte) error {
	if algo == nil || !algo.Hash.IsActual() || !algo.PublicKeyAlgorithm.IsActual() {
		return ge.Pin(&algorithm.UnsupportedAlgorithmError{})
	}

	h := algo.Hash.New()
	h.Write(signedSource)
	digest := h.Sum(nil)

	var err error

	switch algo.PublicKeyAlgorithm {
	case publickeyalgorithm.GostR34102001, publickeyalgorithm.GostR34102012256:
		err = checkSignatureGostR34102001(signature, digest, pubKey)
		if err != nil {
			return ge.Pin(err)
		}

	case publickeyalgorithm.GostR34102012512:
		err = checkSignatureGostR34102012512(signature, digest, pubKey)
		if err != nil {
			return ge.Pin(err)
		}

	case publickeyalgorithm.RSA:
		err = checkSignatureRSA(algo, signature, digest, pubKey)
		if err != nil {
			return ge.Pin(err)
		}

	default:
		return ge.Pin(&algorithm.UnsupportedAlgorithmError{})
	}

	return nil
}

// VerifyPartialChain checks that a given cert is issued by the first parent in the list,
// then continue down the path. It doesn't require the last parent to be a root CA,
// or to be trusted in any truststore. It simply verifies that the chain provided, albeit
// partial, makes sense.
func VerifyPartialChain(cert *Container, parents []*Container) error {
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

	return VerifyPartialChain(parents[0], parents[1:])
}
