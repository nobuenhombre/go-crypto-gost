package certificate

import "errors"

// VerifyDigestError
// en: error - digest verify failed
// ru: ошибка - Верификация подписи не удалась
type VerifyDigestError struct {
}

// Error
// en: error text formation
// ru: формирование текста ошибки
func (e *VerifyDigestError) Error() string {
	return "digest verify failed"
}

// Is
// en: compare with target error
// ru: сравнение с другой ошибкой
func (e *VerifyDigestError) Is(target error) bool {
	var val *VerifyDigestError
	if !errors.As(target, &val) {
		return false
	}

	return true
}
