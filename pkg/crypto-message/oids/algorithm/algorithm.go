// Package algorithm provides
// en: set of constants and functions for working with encryption algorithms in relation to the GOST encryption standard
// ru: набор констант и функции работы с алгоритмами шифрования применительно стандарта шифрования GOST
package algorithm

import "errors"

type Family int

const (
	FamilyRSA Family = iota
	FamilyDSA
	FamilyECDSA
	FamilyGOSTR3410
)

// UnsupportedAlgorithmError
// en: error - Unsupported Algorithm
// ru: ошибка - Неподдерживаемый Алгоритм
type UnsupportedAlgorithmError struct {
}

// Error
// en: error text formation
// ru: формирование текста ошибки
func (e *UnsupportedAlgorithmError) Error() string {
	return "x509: unsupported algorithm"
}

// Is
// en: compare with target error
// ru: сравнение с другой ошибкой
func (e *UnsupportedAlgorithmError) Is(target error) bool {
	var val *UnsupportedAlgorithmError
	if !errors.As(target, &val) {
		return false
	}

	return true
}
