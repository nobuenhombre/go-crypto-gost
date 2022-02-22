package contentInfo

import (
	"encoding/asn1"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

func NewContentInfoFromDER(derData []byte) (*ContentInfo, error) {
	info := &ContentInfo{}

	rest, err := asn1.Unmarshal(derData, info)
	if err != nil {
		return nil, ge.Pin(err)
	}

	if len(rest) > 0 {
		return nil, ge.Pin(asn1.SyntaxError{Msg: "contentInfo trailing derData"})
	}

	return info, nil
}
