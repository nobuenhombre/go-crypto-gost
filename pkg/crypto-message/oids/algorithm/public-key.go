package algorithm

import (
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
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

func GetPublicKeyAlgorithm(oidId oids.ID) (PublicKeyAlgorithm, error) {
	_, err := oids.Get(oidId)
	if err != nil {
		return UnknownAlgorithm, ge.Pin(err)
	}

	list := map[oids.ID]PublicKeyAlgorithm{
		oids.Tc26Gost34102012256:             GostR34102012256,
		oids.Tc26AgreementGost341012256:      GostR34102012256,
		oids.Tc26SignWithDigestGost341012256: GostR34102012256,
		oids.Tc26Gost34102012512:             GostR34102012512,
		oids.Tc26AgreementGost341012512:      GostR34102012512,
		oids.Tc26SignWithDigestGost341012512: GostR34102012512,
	}

	result, found := list[oidId]
	if !found {
		return UnknownAlgorithm, ge.Pin(&ge.NotFoundError{Key: string(oidId)})
	}

	return result, nil
}

func (a PublicKeyAlgorithm) Actual() bool {
	return a != UnknownAlgorithm && a != RSAPSS && a != ECDSA
}

func (a PublicKeyAlgorithm) Family() Family {
	list := map[PublicKeyAlgorithm]Family{
		GostR34102001:    FamilyGOSTR3410,
		GostR34102012256: FamilyGOSTR3410,
		GostR34102012512: FamilyGOSTR3410,
		RSA:              FamilyRSA,
		RSAPSS:           FamilyRSA,
		ECDSA:            FamilyECDSA,
		DSA:              FamilyDSA,
	}

	result, found := list[a]
	if !found {
		return FamilyRSA
	}

	return result
}

// todo - gogostder - can have errors
//const (
//	UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
//	GOST
//)
//
//var publicKeyAlgoName = [...]string{
//	GOST: "GOST",
//}
//
//func (a PublicKeyAlgorithm) String() string {
//	if 0 < a && int(a) < len(publicKeyAlgoName) {
//		return publicKeyAlgoName[a]
//	}
//
//	return strconv.Itoa(int(a))
//}

//func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) PublicKeyAlgorithm {
//	switch {
//	case oid.Equal(oidTc26Gost34102012256):
//		return GOST
//	case oid.Equal(oidTc26Gost34102012512):
//		return GOST
//	case oid.Equal(oidTc26AgreementGost341012256):
//		return GOST
//	case oid.Equal(oidTc26AgreementGost341012512):
//		return GOST
//	case oid.Equal(oidTc26SignWithDigestGost341012256):
//		return GOST
//	case oid.Equal(oidTc26SignWithDigestGost341012512):
//		return GOST
//	}
//
//	return UnknownAlgorithm
//}
