package contentInfo

import (
	"encoding/asn1"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

func (ci *ContentInfo) EncodeToDER() ([]byte, error) {
	derData, err := asn1.Marshal(*ci)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return derData, nil
}
