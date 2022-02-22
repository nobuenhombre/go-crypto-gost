package hash

import (
	"crypto"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost28147"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost34112012256"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost34112012512"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost341194"
	"github.com/nobuenhombre/suikat/pkg/ge"
	"hash"

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

func (h Function) Actual() bool {
	return h != UnknownHashFunction
}

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

type FunctionDetails struct {
	name     string
	function Function
}

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
