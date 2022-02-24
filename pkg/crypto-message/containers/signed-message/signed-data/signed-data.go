package signedData

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers"

	contentInfo "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/content-info"
	rawCertificates "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/raw-certificates"
	signerInfo "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/signer-info"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

type Container struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo.Container
	RawCertificates            rawCertificates.Container `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList    `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo.Container    `asn1:"set"`
}

func DecodeDER(data containers.DER) (*Container, error) {
	sd := &Container{}

	_, err := asn1.Unmarshal(data, sd)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return sd, nil
}
