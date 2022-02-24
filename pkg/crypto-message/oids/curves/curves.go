// Package curves provides
// en: a set of functions for working with *gost3410.Curve in relation to the GOST encryption standard
// ru: набор функции работы с *gost3410.Curve применительно стандарта шифрования GOST
package curves

import (
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

// getList
// en: get a list of *gost3410.Curve and oids.ID matches
// ru: получить список соответствий *gost3410.Curve и oids.ID
func getList() map[oids.ID]*gost3410.Curve {
	return map[oids.ID]*gost3410.Curve{
		oids.GostR34102001CryptoProAParamSet:    gost3410.CurveIdGostR34102001CryptoProAParamSet(),
		oids.GostR34102001CryptoProBParamSet:    gost3410.CurveIdGostR34102001CryptoProBParamSet(),
		oids.GostR34102001CryptoProCParamSet:    gost3410.CurveIdGostR34102001CryptoProCParamSet(),
		oids.GostR34102001CryptoProXchAParamSet: gost3410.CurveIdGostR34102001CryptoProXchAParamSet(),
		oids.GostR34102001CryptoProXchBParamSet: gost3410.CurveIdGostR34102001CryptoProXchBParamSet(),
		oids.Tc26Gost34102012256ParamSetA:       gost3410.CurveIdtc26gost34102012256paramSetA(),
		oids.Tc26Gost34102012256ParamSetB:       gost3410.CurveIdtc26gost34102012256paramSetB(),
		oids.Tc26Gost34102012256ParamSetC:       gost3410.CurveIdtc26gost34102012256paramSetC(),
		oids.Tc26Gost34102012256ParamSetD:       gost3410.CurveIdtc26gost34102012256paramSetD(),
		oids.Tc26Gost34102012512ParamSetA:       gost3410.CurveIdtc26gost341012512paramSetA(),
		oids.Tc26Gost34102012512ParamSetB:       gost3410.CurveIdtc26gost341012512paramSetB(),
		oids.Tc26Gost34102012512ParamSetC:       gost3410.CurveIdtc26gost34102012512paramSetC(),
	}
}

// Get
// en: get *gost3410.Curve by the corresponding oids.ID const
// ru: получить *gost3410.Curve по соответствующей oids.ID константе
func Get(oidId oids.ID) (*gost3410.Curve, error) {
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
