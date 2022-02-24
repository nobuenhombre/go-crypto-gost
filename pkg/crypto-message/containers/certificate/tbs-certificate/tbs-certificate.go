// Package tbsCertificate provides
// en: structure of the Container representation in the asn.1, methods for this structure
//     and the decoding function from DER
// ru: структуру представления Container в asn.1, методы для этой структуры
//     и функцию декодирования из DER
//
// asn.1 - Abstract Syntax Notation One (ASN. 1) is a standard interface description language
// for defining data structures that can be serialized and deserialized in a cross-platform way.
// It is broadly used in telecommunications and computer networking, and especially in cryptography.
// https://en.wikipedia.org/wiki/ASN.1
//
// Container (TBS подразумевает To-Be-Signed) — это основное поле сертификата,
// представляет собой последовательность, содержащую информацию,
// связанную с субъектом сертификата и центром сертификации, который его выдал.
// Container содержит данные, которые используются для вычисления подписи сертификата
// ( цифровой подписи ), которая кодируется с использованием особых правил кодирования ASN.1 ( DER ) X.690 .
package tbsCertificate

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"

	publicKeyInfo "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate/tbs-certificate/public-key-info"
)

type Validity struct {
	NotBefore, NotAfter time.Time
}

// Container - asn.1 x509Certificate::Container structure
// RFC5280
type Container struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           Validity
	Subject            asn1.RawValue
	PublicKeyInfo      publicKeyInfo.Container
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}
