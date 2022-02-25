package signedmessage

import (
	"encoding/pem"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers"

	signeddata "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data"
	// nolint[:lll]
	contentinfo "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/content-info"
	unsigneddata "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/unsigned-data"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/suikat/pkg/fico"
	"github.com/nobuenhombre/suikat/pkg/ge"
	"github.com/nobuenhombre/suikat/pkg/inslice"
)

func DecodeContentInfoContainer(info *contentinfo.Container) (CryptographicMessage, error) {
	signedData, err := signeddata.DecodeDER(info.Content.Bytes)
	if err != nil {
		return nil, ge.Pin(err)
	}

	certificates, err := signedData.RawCertificates.EncodeToCertificates()
	if err != nil {
		return nil, ge.Pin(err)
	}

	content, err := unsigneddata.DecodeDER(signedData.ContentInfo.Content.Bytes)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return &Container{
		Content:      content,
		Certificates: certificates,
		SignedData:   signedData,
	}, nil
}

// DecodeDER - Parse parses a Container from the given DER data.
func DecodeDER(derData []byte) (CryptographicMessage, error) {
	info, err := contentinfo.DecodeDER(derData)
	if err != nil {
		return nil, ge.Pin(err)
	}

	oid, err := oids.Get(oids.SignedData)
	if err != nil {
		return nil, ge.Pin(err)
	}

	if info.IsContentType(oid) {
		return DecodeContentInfoContainer(info)
	}

	return nil, ge.Pin(&ge.MismatchError{
		ComparedItems: "ContentType oid",
		Expected:      oid,
		Actual:        info.ContentType,
	})
}

func DecodePEM(pemData []byte) (CryptographicMessage, error) {
	allow := []string{containers.Default, containers.CMS}

	der, _ := pem.Decode(pemData)
	if der == nil || !inslice.String(der.Type, &allow) {
		return nil, ge.Pin(&ge.MismatchError{
			ComparedItems: "der.Type",
			Expected:      allow,
			Actual:        der.Type,
		})
	}

	return DecodeDER(der.Bytes)
}

func DecodePEMFile(file string) (CryptographicMessage, error) {
	txtFile := fico.TxtFile(file)

	pem, err := txtFile.ReadBytes()
	if err != nil {
		return nil, ge.Pin(err)
	}

	return DecodePEM(pem)
}
