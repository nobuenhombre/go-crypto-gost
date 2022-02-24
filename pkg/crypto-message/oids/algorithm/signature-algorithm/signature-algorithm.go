// Package signatureAlgorithm provides
// en: a set of constants and functions for working with encryption algorithms for signatures
//     in relation to the GOST encryption standard
// ru: набор констант и функции работы с алгоритмами шифрования для подписей
//     применительно стандарта шифрования GOST
package signatureAlgorithm

import (
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm"
	publicKeyAlgorithm "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm/public-key-algorithm"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/hash"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

type SignatureAlgorithm struct {
	Name               string
	PublicKeyAlgorithm publicKeyAlgorithm.PublicKeyAlgorithm
	Hash               hash.Function
}

// GetFamily
// en: which family does this algorithm belong to?
// ru: к какому семейству относится данный алгоритм?
func (sa SignatureAlgorithm) GetFamily() algorithm.Family {
	return sa.PublicKeyAlgorithm.GetFamily()
}

// getList
// en: get a list of signature algorithms and oids.ID matches
// ru: получить список соответствий алгоритмов подписи и oids.ID
func getList() map[oids.ID]*SignatureAlgorithm {
	return map[oids.ID]*SignatureAlgorithm{
		oids.SignatureSHA1WithRSA: {
			"SHA1-RSA",
			publicKeyAlgorithm.RSA,
			hash.SHA1,
		},
		oids.ISOSignatureSHA1WithRSA: {
			"SHA1-RSA",
			publicKeyAlgorithm.RSA,
			hash.SHA1,
		},
		oids.SignatureSHA256WithRSA: {
			"SHA256-RSA",
			publicKeyAlgorithm.RSA,
			hash.SHA256,
		},
		oids.SignatureSHA384WithRSA: {
			"SHA384-RSA",
			publicKeyAlgorithm.RSA,
			hash.SHA384,
		},
		oids.SignatureSHA512WithRSA: {
			"SHA512-RSA",
			publicKeyAlgorithm.RSA,
			hash.SHA512,
		},
		oids.SignatureGostR34102001: {
			"GOST-3410_2001",
			publicKeyAlgorithm.GostR34102001,
			hash.UnknownHashFunction,
		},
		oids.SignatureGostR34102001GostR341194: {
			"GOST-3410_2001-3411_94",
			publicKeyAlgorithm.GostR34102001,
			hash.GostR341194,
		},
		oids.Tc26Gost34102012256: {
			"GOST-3410_12_256",
			publicKeyAlgorithm.GostR34102012256,
			hash.UnknownHashFunction,
		},
		oids.Tc26SignWithDigestGost341012256: {
			"GOST-3410_12_256-3411_12",
			publicKeyAlgorithm.GostR34102012256,
			hash.GostR34112012256,
		},
		oids.Tc26Gost34102012512: {
			"GOST-3410_12_512",
			publicKeyAlgorithm.GostR34102012512,
			hash.UnknownHashFunction,
		},
		oids.Tc26SignWithDigestGost341012512: {
			"GOST-3410_12_512-3411_12",
			publicKeyAlgorithm.GostR34102012512,
			hash.GostR34112012512,
		},
	}
}

// Get
// en: get signature algorithm by the corresponding oids.ID const
// ru: получить алгоритм подписи по соответствующей oids.ID константе
func Get(oidId oids.ID) (*SignatureAlgorithm, error) {
	_, err := oids.Get(oidId)
	if err != nil {
		return nil, ge.Pin(err)
	}

	list := getList()

	result, found := list[oidId]
	if !found {
		return nil, ge.Pin(&ge.NotFoundError{Key: string(oidId)})
	}

	return result, nil
}
