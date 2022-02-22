package pemFormat

import "errors"

const (
	Certificate = "CERTIFICATE"
	PrivateKey  = "PRIVATE KEY"
	Default     = "PKCS7"
	CMS         = "CMS"
)

type TrailingDataError struct {
}

func (e *TrailingDataError) Error() string {
	return "x509: trailing data after RSA public key"
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
