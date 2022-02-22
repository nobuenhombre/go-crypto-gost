package contentInfo

import "encoding/asn1"

// ContentInfo asn.1 CMS representation RFC5652
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

func (ci *ContentInfo) IsContentType(oid asn1.ObjectIdentifier) bool {
	return ci.ContentType.Equal(oid)
}
