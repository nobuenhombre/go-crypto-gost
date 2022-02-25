// Package publickeyalgorithm provides
// en: a set of constants and functions for working with encryption algorithms for public keys
//     in relation to the GOST encryption standard
// ru: набор констант и функции работы с алгоритмами шифрования для публичных ключей
//     применительно стандарта шифрования GOST
package publickeyalgorithm

import (
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

type PublicKeyAlgorithm string

const (
	UnknownAlgorithm PublicKeyAlgorithm = "UnknownAlgorithm"
	RSA              PublicKeyAlgorithm = "RSA"
	DSA              PublicKeyAlgorithm = "DSA"
	RSAPSS           PublicKeyAlgorithm = "RSAPSS"
	ECDSA            PublicKeyAlgorithm = "ECDSA"
	GostR34102001    PublicKeyAlgorithm = "GostR34102001"
	GostR34102012256 PublicKeyAlgorithm = "GostR34102012256"
	GostR34102012512 PublicKeyAlgorithm = "GostR34102012512"
)

// IsActual
// en: is this algorithm actual?
// ru: актуален ли данный алгоритм?
func (a PublicKeyAlgorithm) IsActual() bool {
	return a != UnknownAlgorithm && a != RSAPSS && a != ECDSA
}

// GetFamily
// en: which family does this algorithm belong to?
// ru: к какому семейству относится данный алгоритм?
func (a PublicKeyAlgorithm) GetFamily() algorithm.Family {
	list := map[PublicKeyAlgorithm]algorithm.Family{
		GostR34102001:    algorithm.FamilyGOSTR3410,
		GostR34102012256: algorithm.FamilyGOSTR3410,
		GostR34102012512: algorithm.FamilyGOSTR3410,
		RSA:              algorithm.FamilyRSA,
		RSAPSS:           algorithm.FamilyRSA,
		ECDSA:            algorithm.FamilyECDSA,
		DSA:              algorithm.FamilyDSA,
	}

	result, found := list[a]
	if !found {
		return algorithm.FamilyRSA
	}

	return result
}

// getList
// en: get a list of public key algorithms and oids.ID matches
// ru: получить список соответствий алгоритмов публичного ключа и oids.ID
func getList() map[oids.ID]PublicKeyAlgorithm {
	return map[oids.ID]PublicKeyAlgorithm{
		oids.Tc26Gost34102012256:             GostR34102012256,
		oids.Tc26AgreementGost341012256:      GostR34102012256,
		oids.Tc26SignWithDigestGost341012256: GostR34102012256,
		oids.Tc26Gost34102012512:             GostR34102012512,
		oids.Tc26AgreementGost341012512:      GostR34102012512,
		oids.Tc26SignWithDigestGost341012512: GostR34102012512,
	}
}

// Get
// en: get public key algorithm by the corresponding oids.ID const
// ru: получить алгоритм публичного ключа по соответствующей oids.ID константе
func Get(oidID oids.ID) (PublicKeyAlgorithm, error) {
	_, err := oids.Get(oidID)
	if err != nil {
		return UnknownAlgorithm, ge.Pin(err)
	}

	list := getList()

	result, found := list[oidID]
	if !found {
		return UnknownAlgorithm, ge.Pin(&ge.NotFoundError{Key: string(oidID)})
	}

	return result, nil
}
