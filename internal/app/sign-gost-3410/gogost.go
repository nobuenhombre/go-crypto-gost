package signGost3410

import (
	"crypto/rand"
	"fmt"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/hash"
	"reflect"

	//goGostCrypto "github.com/ftomza/go-gost-crypto"
	"io"

	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

func GetDigest(data []byte, hashFunc hash.Function) ([]byte, error) {
	hashFuncInternal := hashFunc.New()

	// hash.Hash
	// hashFunc := gost34112012256.New()

	_, err := hashFuncInternal.Write(data)
	if err != nil {
		return []byte{}, ge.Pin(err)
	}

	// Дайджест
	digest := hashFuncInternal.Sum(nil)

	return digest, nil
}

func GeneratePrivateKey(curve *gost3410.Curve) (*gost3410.PrivateKey, error) {
	privateRaw := make([]byte, int(32))

	_, err := io.ReadFull(rand.Reader, privateRaw)
	if err != nil {
		return nil, ge.Pin(err)
	}

	//type PrivateKey struct {
	//	C   *Curve
	//	Key *big.Int
	//}
	privateKey, err := gost3410.NewPrivateKey(curve, privateRaw)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return privateKey, nil
}

func ExtractPublicKeyGOST(curve *gost3410.Curve, privateKey *gost3410.PrivateKey) (*gost3410.PublicKey, error) {
	//type PublicKey struct {
	//	C *Curve
	//	X *big.Int
	//	Y *big.Int
	//}
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		return nil, ge.Pin(err)
	}

	publicKeyRaw := publicKey.Raw()

	publicKeyGost, err := gost3410.NewPublicKey(curve, publicKeyRaw)
	if err != nil {
		return nil, ge.Pin(err)
	}

	x := reflect.DeepEqual(publicKey, publicKeyGost)
	fmt.Printf("deep equal %v", x)

	return publicKeyGost, nil
}
