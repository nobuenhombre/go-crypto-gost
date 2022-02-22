package signedMessage

import (
	"encoding/pem"
	signedData "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/content-info"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/unsigned-data"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	pemFormat "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/pem-format"
	"github.com/nobuenhombre/suikat/pkg/fico"
	"github.com/nobuenhombre/suikat/pkg/ge"
	"github.com/nobuenhombre/suikat/pkg/inslice"
)

func NewCryptoMessageFromContentInfo(info *contentInfo.ContentInfo) (CryptographicMessage, error) {
	signedData, err := signedData.NewSignedDataFromInfoContent(info.Content.Bytes)
	if err != nil {
		return nil, ge.Pin(err)
	}

	certificates, err := signedData.RawCertificates.EncodeToCertificates()
	if err != nil {
		return nil, ge.Pin(err)
	}

	content, err := unsignedData.NewUnsignedData(signedData.ContentInfo.Content.Bytes)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return &CMS{
		Content:      content,
		Certificates: certificates,
		SignedData:   signedData,
	}, nil
}

// NewCryptoMessageFromDER - Parse parses a CMS from the given DER data.
func NewCryptoMessageFromDER(derData []byte) (CryptographicMessage, error) {
	info, err := contentInfo.NewContentInfoFromDER(derData)
	if err != nil {
		return nil, ge.Pin(err)
	}

	oid, err := oids.Get(oids.SignedData)
	if err != nil {
		return nil, ge.Pin(err)
	}

	if info.IsContentType(oid) {
		return NewCryptoMessageFromContentInfo(info)
	} else {
		return nil, ge.Pin(&ge.MismatchError{
			ComparedItems: "ContentType oid",
			Expected:      oid,
			Actual:        info.ContentType,
		})
	}
}

func NewCryptoMessageFromPEM(pemData []byte) (CryptographicMessage, error) {
	allow := []string{pemFormat.Default, pemFormat.CMS}

	der, _ := pem.Decode(pemData)
	if der == nil || !inslice.String(der.Type, &allow) {
		return nil, ge.Pin(&ge.MismatchError{
			ComparedItems: "der.Type",
			Expected:      allow,
			Actual:        der.Type,
		})
	}

	return NewCryptoMessageFromDER(der.Bytes)
}

func NewCryptoMessageFromFile(file string) (CryptographicMessage, error) {
	txtFile := fico.TxtFile(file)
	pem, err := txtFile.ReadBytes()
	if err != nil {
		return nil, ge.Pin(err)
	}

	return NewCryptoMessageFromPEM(pem)
}
