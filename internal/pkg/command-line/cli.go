package commandline

import "github.com/nobuenhombre/suikat/pkg/clivar"

type Config struct {
	PrivateKeyFile  string `cli:"PrivateKeyFile[Путь к файлу приватного ключа]:string=private.key.pem"`
	PublicKeyFile   string `cli:"PublicKeyFile[Путь к файлу публичного ключа]:string=public.key.pem"`
	MessageFile     string `cli:"MessageFile[Путь к файлу сообщения]:string=message.txt"`
	MessageFileSign string `cli:"MessageFileSign[Путь к файлу подписи сообщения]:string=message.txt.sig"`
}

func (cfg *Config) Load() error {
	return clivar.Load(cfg)
}
