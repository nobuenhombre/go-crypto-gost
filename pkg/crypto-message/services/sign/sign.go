package sign

import (
	"bytes"
	"encoding/pem"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	privatekey "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/private-key"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

type Service interface {
	Sign(message []byte, publicKeyPEM, privateKeyPEM containers.PEM) (signed containers.PEM, err error)
}

type Config struct{}

func New() Service {
	return &Config{}
}

func (c *Config) Sign(message []byte, publicKeyPEM, privateKeyPEM containers.PEM) (signed containers.PEM, err error) {
	publicKeys, err := certificate.DecodePEM(publicKeyPEM)
	if err != nil {
		return nil, ge.Pin(err)
	}

	if len(publicKeys) == 0 {
		return nil, ge.New("empty public keys")
	}

	publicKey := publicKeys[0]

	privateKey, err := privatekey.DecodePEM(privateKeyPEM)
	if err != nil {
		return nil, ge.Pin(err)
	}

	toBeSigned, err := NewSignedData(message)
	if err != nil {
		return nil, ge.Pin(err)
	}

	err = toBeSigned.SignWithoutAttr(publicKey, privateKey, SignerInfoConfig{})
	if err != nil {
		return nil, ge.Pin(err)
	}

	// Detach signature, omit if you want an embedded signature
	err = toBeSigned.Detach()
	if err != nil {
		return nil, ge.Pin(err)
	}

	signed, err = toBeSigned.Finish()
	if err != nil {
		return nil, ge.Pin(err)
	}

	var buffer bytes.Buffer

	err = pem.Encode(&buffer, &pem.Block{Type: containers.Default, Bytes: signed})
	if err != nil {
		return nil, ge.Pin(err)
	}

	return buffer.Bytes(), nil
}
