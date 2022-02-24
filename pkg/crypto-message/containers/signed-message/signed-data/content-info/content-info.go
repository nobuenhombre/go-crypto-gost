package contentInfo

import "encoding/asn1"

// Container asn.1 CMS representation RFC5652
type Container struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

func (ci *Container) IsContentType(oid asn1.ObjectIdentifier) bool {
	return ci.ContentType.Equal(oid)
}
