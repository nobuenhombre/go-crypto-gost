package signerInfo

import (
	"encoding/asn1"
	"sort"
)

type Attributes struct {
	types  []asn1.ObjectIdentifier
	values []interface{}
}

// Add adds the attribute, maintaining insertion order
func (attrs *Attributes) Add(attrType asn1.ObjectIdentifier, value interface{}) {
	attrs.types = append(attrs.types, attrType)
	attrs.values = append(attrs.values, value)
}

func (attrs *Attributes) ForMarshalling() ([]Attribute, error) {
	sortables := make(attributeSet, len(attrs.types))

	for i := range sortables {
		attrType := attrs.types[i]
		attrValue := attrs.values[i]

		asn1Value, err := asn1.Marshal(attrValue)
		if err != nil {
			return nil, err
		}

		attr := Attribute{
			Type:  attrType,
			Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: asn1Value}, // 17 == SET tag
		}

		encoded, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}

		sortables[i] = sortableAttribute{
			SortKey:   encoded,
			Attribute: attr,
		}
	}

	sort.Sort(sortables)

	return sortables.Attributes(), nil
}
