package algorithm

import "errors"

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
