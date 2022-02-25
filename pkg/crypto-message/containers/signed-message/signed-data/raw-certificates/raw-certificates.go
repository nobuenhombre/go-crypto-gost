package rawcertificates

import (
	"encoding/asn1"
)

type Container struct {
	Raw asn1.RawContent
}
