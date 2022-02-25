package signerinfo

import (
	"bytes"
)

type sortableAttribute struct {
	SortKey   []byte
	Attribute Attribute
}

type attributeSet []sortableAttribute

func (sa attributeSet) Len() int {
	return len(sa)
}

func (sa attributeSet) Less(i, j int) bool {
	return bytes.Compare(sa[i].SortKey, sa[j].SortKey) < 0
}

func (sa attributeSet) Swap(i, j int) {
	sa[i], sa[j] = sa[j], sa[i]
}

func (sa attributeSet) Attributes() []Attribute {
	attrs := make([]Attribute, len(sa))

	for i, attr := range sa {
		attrs[i] = attr.Attribute
	}

	return attrs
}
