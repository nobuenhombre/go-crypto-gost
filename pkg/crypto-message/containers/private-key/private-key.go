package privateKey

import (
	"crypto/x509/pkix"
)

type PKCS8 struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}
