package publicKeyInfo

import (
	"encoding/asn1"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers"

	"github.com/nobuenhombre/suikat/pkg/ge"
)

func DecodeDER(der containers.DER) (*Container, error) {
	pki := &Container{}

	rest, err := asn1.Unmarshal(der, pki)
	if err != nil {
		return nil, ge.Pin(err)
	}

	if len(rest) != 0 {
		return nil, ge.Pin(&containers.TrailingDataError{})
	}

	return pki, nil
}
