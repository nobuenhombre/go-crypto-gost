package algorithm

import (
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/hash"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

type SignatureAlgorithm struct {
	Name               string
	PublicKeyAlgorithm PublicKeyAlgorithm
	Hash               hash.Function
}

func (sa SignatureAlgorithm) Family() Family {
	return sa.PublicKeyAlgorithm.Family()
}

func GetSignatureAlgorithm(oidId oids.ID) (*SignatureAlgorithm, error) {
	_, err := oids.Get(oidId)
	if err != nil {
		return nil, ge.Pin(err)
	}

	list := map[oids.ID]*SignatureAlgorithm{
		oids.SignatureSHA1WithRSA: {
			"SHA1-RSA",
			RSA,
			hash.SHA1,
		},
		oids.ISOSignatureSHA1WithRSA: {
			"SHA1-RSA",
			RSA,
			hash.SHA1,
		},
		oids.SignatureSHA256WithRSA: {
			"SHA256-RSA",
			RSA,
			hash.SHA256,
		},
		oids.SignatureSHA384WithRSA: {
			"SHA384-RSA",
			RSA,
			hash.SHA384,
		},
		oids.SignatureSHA512WithRSA: {
			"SHA512-RSA",
			RSA,
			hash.SHA512,
		},
		/*
			{"SHA256-RSAPSS", oidSignatureRSAPSS, RSAPSS, SHA256},
			{"SHA384-RSAPSS", oidSignatureRSAPSS, RSAPSS, SHA384},
			{"SHA512-RSAPSS", oidSignatureRSAPSS, RSAPSS, SHA512},

			{ "DSA-SHA1", oidSignatureDSAWithSHA1, DSA, SHA1},
			{ "DSA-SHA256", oidSignatureDSAWithSHA256, DSA, SHA256},
			{ "ECDSA-SHA1", oidSignatureECDSAWithSHA1, ECDSA, SHA1},
			{ "ECDSA-SHA256", oidSignatureECDSAWithSHA256, ECDSA, SHA256},
			{ "ECDSA-SHA384", oidSignatureECDSAWithSHA384, ECDSA, SHA384},
			{ "ECDSA-SHA512", oidSignatureECDSAWithSHA512, ECDSA, SHA512},
		*/
		//GOST-R  https://www.cryptopro.ru/sites/default/files/products/tls/tk26iok.pdf
		oids.SignatureGostR34102001: {
			"GOST-3410_2001",
			GostR34102001,
			hash.UnknownHashFunction,
		},
		oids.SignatureGostR34102001GostR341194: {
			"GOST-3410_2001-3411_94",
			GostR34102001,
			hash.GostR341194,
		},

		oids.Tc26Gost34102012256: {
			"GOST-3410_12_256",
			GostR34102012256,
			hash.UnknownHashFunction,
		},
		oids.Tc26SignWithDigestGost341012256: {
			"GOST-3410_12_256-3411_12",
			GostR34102012256,
			hash.GostR34112012256,
		},

		oids.Tc26Gost34102012512: {
			"GOST-3410_12_512",
			GostR34102012512,
			hash.UnknownHashFunction,
		},
		oids.Tc26SignWithDigestGost341012512: {
			"GOST-3410_12_512-3411_12",
			GostR34102012512,
			hash.GostR34112012512,
		},
	}

	result, found := list[oidId]
	if !found {
		return nil, ge.Pin(&ge.NotFoundError{Key: string(oidId)})
	}

	return result, nil
}

//var signatureAlgorithmDetails = []SignatureAlgorithm{
//
//	{"SHA1-RSA", oidSignatureSHA1WithRSA, RSA, SHA1},
//	{"SHA1-RSA", oidISOSignatureSHA1WithRSA, RSA, SHA1},
//	{"SHA256-RSA", oidSignatureSHA256WithRSA, RSA, SHA256},
//	{"SHA384-RSA", oidSignatureSHA384WithRSA, RSA, SHA384},
//	{"SHA512-RSA", oidSignatureSHA512WithRSA, RSA, SHA512},
//	/*
//		{"SHA256-RSAPSS", oidSignatureRSAPSS, RSAPSS, SHA256},
//		{"SHA384-RSAPSS", oidSignatureRSAPSS, RSAPSS, SHA384},
//		{"SHA512-RSAPSS", oidSignatureRSAPSS, RSAPSS, SHA512},
//
//		{ "DSA-SHA1", oidSignatureDSAWithSHA1, DSA, SHA1},
//		{ "DSA-SHA256", oidSignatureDSAWithSHA256, DSA, SHA256},
//		{ "ECDSA-SHA1", oidSignatureECDSAWithSHA1, ECDSA, SHA1},
//		{ "ECDSA-SHA256", oidSignatureECDSAWithSHA256, ECDSA, SHA256},
//		{ "ECDSA-SHA384", oidSignatureECDSAWithSHA384, ECDSA, SHA384},
//		{ "ECDSA-SHA512", oidSignatureECDSAWithSHA512, ECDSA, SHA512},
//	*/
//	//GOST-R  https://www.cryptopro.ru/sites/default/files/products/tls/tk26iok.pdf
//	{"GOST-3410_2001", oidSignatureGostR34102001, GOSTR3410_2001, UnknownHashFunction},
//	{"GOST-3410_2001-3411_94", oidSignatureGostR34102001GostR341194, GOSTR3410_2001, GostR341194},
//
//	{"GOST-3410_12_256", oidTc26Gost34102012256, GOSTR3410_2012_256, UnknownHashFunction},
//	{"GOST-3410_12_256-3411_12", oidTc26SignWithDigestGost341012256, GOSTR3410_2012_256, GostR34112012256},
//
//	{"GOST-3410_12_512", oidTc26Gost34102012512, GOSTR3410_2012_512, UnknownHashFunction},
//	{"GOST-3410_12_512-3411_12", oidTc26SignWithDigestGost341012512, GOSTR3410_2012_512, GostR34112012512},
//}
//
//func GetSignatureAlgorithmForOid(oid asn1.ObjectIdentifier) *SignatureAlgorithm {
//	for _, details := range signatureAlgorithmDetails {
//		if details.oid.Equal(oid) {
//			return &details
//		}
//	}
//
//	return nil
//}
