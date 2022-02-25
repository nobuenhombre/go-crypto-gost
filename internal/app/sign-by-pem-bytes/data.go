package signbypembytes

import (
	commandline "github.com/nobuenhombre/go-crypto-gost/internal/pkg/command-line"
	"github.com/nobuenhombre/suikat/pkg/fico"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

func GetBytes(cfg *commandline.Config) (sourceMessage, publicKeyPEMBytes, privateKeyPEMBytes []byte, err error) {
	// 2.1
	// Файл с исходным сообщением
	sourceMessageFile := fico.TxtFile(cfg.MessageFile)

	sourceMessage, err = sourceMessageFile.ReadBytes()
	if err != nil {
		return nil, nil, nil, ge.Pin(err)
	}

	// 2.2
	// Файл публичного ключа в формате PEM
	publicKeyFileFile := fico.TxtFile(cfg.PublicKeyFile)

	publicKeyPEMBytes, err = publicKeyFileFile.ReadBytes()
	if err != nil {
		return nil, nil, nil, ge.Pin(err)
	}

	// 2.3
	// Файл приватного ключа в формате PEM
	privateKeyFile := fico.TxtFile(cfg.PrivateKeyFile)

	privateKeyPEMBytes, err = privateKeyFile.ReadBytes()
	if err != nil {
		return nil, nil, nil, ge.Pin(err)
	}

	return
}
