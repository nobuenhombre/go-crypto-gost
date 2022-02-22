package signedData

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/content-info"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/raw-certificates"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/signer-info"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

type SignedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo.ContentInfo
	RawCertificates            rawCertificates.RawCertificates `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList          `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo.SignerInfo         `asn1:"set"`
}

func NewSignedDataFromInfoContent(data []byte) (*SignedData, error) {
	sd := &SignedData{}

	_, err := asn1.Unmarshal(data, sd)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return sd, nil
}
