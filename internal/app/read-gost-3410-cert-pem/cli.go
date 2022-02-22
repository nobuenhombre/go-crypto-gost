package readGost3410CertPem

import "github.com/nobuenhombre/suikat/pkg/clivar"

type CliConfig struct {
	PrivateKeyFile  string `cli:"PrivateKeyFile[Путь к файлу приватного ключа]:string=private.key.pem"`
	PublicKeyFile   string `cli:"PublicKeyFile[Путь к файлу публичного ключа]:string=public.key.pem"`
	MessageFile     string `cli:"MessageFile[Путь к файлу сообщения]:string=message.txt"`
	MessageFileSign string `cli:"MessageFileSign[Путь к файлу подписи сообщения]:string=message.txt.sig"`
}

func (cfg *CliConfig) Load() error {
	return clivar.Load(cfg)
}
