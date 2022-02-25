package privatekey

import (
	"crypto/x509/pkix"
)

// Container - asn.1 Private Key structure
type Container struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}
