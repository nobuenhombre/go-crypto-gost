// TBSCertificate (TBS подразумевает To-Be-Signed) — это основное поле сертификата,
// представляет собой последовательность, содержащую информацию,
// связанную с субъектом сертификата и центром сертификации, который его выдал.
// TBSCertificate содержит данные, которые используются для вычисления подписи сертификата
// ( цифровой подписи ), которая кодируется с использованием особых правил кодирования ASN.1 ( DER ) X.690 .

package tbsCertificate

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate/tbs-certificate/public-key-info"
	"math/big"
	"time"
)

type Validity struct {
	NotBefore, NotAfter time.Time
}

//type publicKeyInfo struct {
//	Raw       asn1.RawContent
//	Algorithm pkix.AlgorithmIdentifier
//	PublicKey asn1.BitString
//}

// TBSCertificate - asn.1 x509Certificate::TBSCertificate structure
// RFC5280
type TBSCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           Validity
	Subject            asn1.RawValue
	PublicKeyInfo      publicKeyInfo.PublicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

//type tbsCertificate struct {
//	Raw                asn1.RawContent
//	Version            int `asn1:"optional,explicit,default:0,tag:0"`
//	SerialNumber       *big.Int
//	SignatureAlgorithm pkix.AlgorithmIdentifier
//	Issuer             asn1.RawValue
//	Validity           validity
//	Subject            asn1.RawValue
//	PublicKeyInfo      publicKeyInfo
//	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
//	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
//	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
//}
