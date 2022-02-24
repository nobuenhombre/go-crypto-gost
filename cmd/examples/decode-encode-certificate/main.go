package main

import (
	"bytes"
	"log"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	"github.com/nobuenhombre/suikat/pkg/fico"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

func main() {
	certFile := fico.TxtFile("public.key.pem")
	certPEM, err := certFile.ReadBytes()
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	caList, err := certificate.DecodePEM(certPEM)
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	pem, err := caList[0].EncodeToPEM()
	if err != nil {
		log.Fatal(ge.Pin(err))
	}

	if bytes.Compare(certPEM, pem) != 0 {
		log.Fatal(ge.Pin(&ge.MismatchError{
			ComparedItems: "certPEM, pem",
			Expected:      certPEM,
			Actual:        pem,
		}))
	}

	certEncodedFile := fico.TxtFile("out.public.key.pem")
	err = certEncodedFile.Write(string(pem))
	if err != nil {
		log.Fatal(ge.Pin(err))
	}
}
