package contentinfo

import (
	"encoding/asn1"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers"

	"github.com/nobuenhombre/suikat/pkg/ge"
)

func DecodeDER(derData containers.DER) (*Container, error) {
	info := &Container{}

	rest, err := asn1.Unmarshal(derData, info)
	if err != nil {
		return nil, ge.Pin(err)
	}

	if len(rest) > 0 {
		return nil, ge.Pin(&containers.TrailingDataError{})
	}

	return info, nil
}
