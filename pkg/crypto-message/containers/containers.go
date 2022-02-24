// Package containers provides
// en: a set of constants and functions for working with PEM and DER packaging formats
// ru: набор констант и функции работы с PEM и DER форматами упаковки
package containers

import "errors"

const (
	Certificate = "CERTIFICATE"
	PrivateKey  = "PRIVATE KEY"
	Default     = "PKCS7"
	CMS         = "CMS"
)

// PEM
// (originally “Privacy Enhanced Mail”) is the most common format for X.509 certificates, CSRs,
// and cryptographic keys. A PEM file is a text file containing one or more items in Base64 ASCII encoding,
// each with plain-text headers and footers (e.g. -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----).
// A single PEM file could contain an end-entity certificate, a private key,
// or multiple certificates forming a complete chain of trust.
// PEM files are usually seen with the extensions .crt, .pem, .cer, and .key (for private keys),
// but you may also see them with different extensions.
// For example, the SSL.com CA bundle file available
// from the download table in a certificate order has the extension .ca-bundle.
type PEM []byte

// DER
// (Distinguished Encoding Rules) is a binary encoding for X.509 certificates and private keys.
// Unlike PEM, DER-encoded files do not contain plain text statements such as -----BEGIN CERTIFICATE-----.
// DER files are most commonly seen in Java contexts.
// DER-encoded files are usually found with the extensions .der and .cer.
type DER []byte

// TrailingDataError
// en: error - trailing data
// ru: ошибка - лишние данные
type TrailingDataError struct {
}

// Error
// en: error text formation
// ru: формирование текста ошибки
func (e *TrailingDataError) Error() string {
	return "x509: trailing data"
}

// Is
// en: compare with target error
// ru: сравнение с другой ошибкой
func (e *TrailingDataError) Is(target error) bool {
	var val *TrailingDataError
	if !errors.As(target, &val) {
		return false
	}

	return true
}
