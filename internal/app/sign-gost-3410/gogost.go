package signgost3410

import (
	"crypto/rand"

	privateKeyPkg "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/private-key"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/hash"
	"github.com/nobuenhombre/suikat/pkg/chunks"

	"io"

	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

func GetDigest(data []byte, hashFunc hash.Function) ([]byte, error) {
	hashFuncInternal := hashFunc.New()

	_, err := hashFuncInternal.Write(data)
	if err != nil {
		return []byte{}, ge.Pin(err)
	}

	// Дайджест
	digest := chunks.ReverseFullBytes(hashFuncInternal.Sum(nil))

	return digest, nil
}

func GeneratePrivateKey(curve *gost3410.Curve) (*gost3410.PrivateKey, error) {
	privateRaw := make([]byte, int(privateKeyPkg.Length))

	_, err := io.ReadFull(rand.Reader, privateRaw)
	if err != nil {
		return nil, ge.Pin(err)
	}

	privateKey, err := gost3410.NewPrivateKey(curve, privateRaw)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return privateKey, nil
}

func ExtractPublicKeyGOST(curve *gost3410.Curve, privateKey *gost3410.PrivateKey) (*gost3410.PublicKey, error) {
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		return nil, ge.Pin(err)
	}

	publicKeyRaw := publicKey.Raw()

	publicKeyGost, err := gost3410.NewPublicKey(curve, publicKeyRaw)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return publicKeyGost, nil
}
