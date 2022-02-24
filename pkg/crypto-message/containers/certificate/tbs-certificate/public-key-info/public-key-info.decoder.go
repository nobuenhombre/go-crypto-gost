package publicKeyInfo

import (
	"encoding/asn1"

	pemFormat "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers"

	"github.com/nobuenhombre/suikat/pkg/ge"
)

func NewPublicKeyInfoFromDER(derData []byte) (*PublicKeyInfo, error) {
	pki := &PublicKeyInfo{}

	rest, err := asn1.Unmarshal(derData, pki)
	if err != nil {
		return nil, ge.Pin(err)
	}

	if len(rest) != 0 {
		return nil, ge.Pin(&pemFormat.TrailingDataError{})
	}

	return pki, nil
}
