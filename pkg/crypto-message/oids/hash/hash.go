// Package hash provides
// en: a set of constants and functions for working with hash functions in relation to the GOST encryption standard
// ru: набор констант и функции работы с хеш функциями применительно стандарта шифрования GOST
package hash

import (
	"crypto"
	"hash"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost28147"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost34112012256"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost34112012512"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost341194"
	"github.com/nobuenhombre/suikat/pkg/ge"

	_ "crypto/sha256"
	_ "crypto/sha512"
)

type Function string

const (
	UnknownHashFunction Function = "UnknownHashFunction"
	SHA1                Function = "SHA1"
	SHA256              Function = "SHA256"
	SHA384              Function = "SHA384"
	SHA512              Function = "SHA512"
	GostR341194         Function = "GostR341194"
	GostR34112012256    Function = "GostR34112012256" //Stribog GOST R 34.11-2012 256-bit
	GostR34112012512    Function = "GostR34112012512" //Stribog GOST R 34.11-2012 512-bit
)

// IsActual
// en: is this hash function actual?
// ru: актуальна ли данная хеш функция?
func (h Function) IsActual() bool {
	return h != UnknownHashFunction
}

// CryptoHash
// en: returns standard hash functions
// ru: возвращает стандартные хеш функции
func (h Function) CryptoHash() crypto.Hash {
	switch h {
	case SHA1:
		return crypto.SHA1
	case SHA256:
		return crypto.SHA256
	case SHA384:
		return crypto.SHA384
	case SHA512:
		return crypto.SHA512
	default:
		return crypto.Hash(0)
	}
}

// New
// en: returns a new hash.Hash calculating the given hash function.
// ru: возвращает новый hash.Hash, вычисляющий заданную хэш-функцию.
func (h Function) New() hash.Hash {
	switch h {
	case SHA1:
		return crypto.SHA1.New()
	case SHA256:
		return crypto.SHA256.New()
	case SHA384:
		return crypto.SHA384.New()
	case SHA512:
		return crypto.SHA512.New()
	case GostR341194:
		return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
	case GostR34112012256:
		return gost34112012256.New()
	case GostR34112012512:
		return gost34112012512.New()
	default:
		return nil
	}
}

// getList
// en: get a list of hash functions and oids.ID matches
// ru: получить список соответствий Хеш Функций и oids.ID
func getList() map[oids.ID]Function {
	return map[oids.ID]Function{
		oids.HashFuncSHA1:        SHA1,
		oids.HashFuncSHA256:      SHA256,
		oids.HashFuncSHA384:      SHA384,
		oids.HashFuncSHA512:      SHA512,
		oids.HashFuncGostR341194: GostR341194,
		oids.Tc26Gost34112012256: GostR34112012256,
		oids.Tc26Gost34112012512: GostR34112012512,
	}
}

// Get
// en: get hash function by the corresponding oids.ID const
// ru: получить хэш функцию по соответствующей oids.ID константе
func Get(oidId oids.ID) (Function, error) {
	_, err := oids.Get(oidId)
	if err != nil {
		return UnknownHashFunction, ge.Pin(err)
	}

	list := getList()

	result, found := list[oidId]
	if !found {
		return UnknownHashFunction, ge.Pin(&ge.NotFoundError{Key: string(oidId)})
	}

	return result, nil
}
