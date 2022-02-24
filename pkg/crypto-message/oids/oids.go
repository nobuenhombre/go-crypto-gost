// Package oids provides
// en: a set of constants and functions for working with ASN.1 OBJECT IDENTIFIER in relation to the GOST encryption standard
// ru: набор констант и функции работы с ASN.1 OBJECT IDENTIFIER применительно стандарта шифрования GOST
package oids

import (
	"encoding/asn1"
	"fmt"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

type ID string

const (
	Unknown                            ID = "Unknown"
	Tc26Gost34102012256                ID = "Tc26Gost34102012256"
	Tc26Gost34102012512                ID = "Tc26Gost34102012512"
	Tc26Gost34112012256                ID = "Tc26Gost34112012256"
	Tc26Gost34112012512                ID = "Tc26Gost34112012512"
	Tc26SignWithDigestGost341012256    ID = "Tc26SignWithDigestGost341012256"
	Tc26SignWithDigestGost341012512    ID = "Tc26SignWithDigestGost341012512"
	Tc26AgreementGost341012256         ID = "Tc26AgreementGost341012256"
	Tc26AgreementGost341012512         ID = "Tc26AgreementGost341012512"
	GostR34102001CryptoProAParamSet    ID = "GostR34102001CryptoProAParamSet"
	GostR34102001CryptoProBParamSet    ID = "GostR34102001CryptoProBParamSet"
	GostR34102001CryptoProCParamSet    ID = "GostR34102001CryptoProCParamSet"
	GostR34102001CryptoProXchAParamSet ID = "GostR34102001CryptoProXchAParamSet"
	GostR34102001CryptoProXchBParamSet ID = "GostR34102001CryptoProXchBParamSet"
	Tc26Gost34102012256ParamSetA       ID = "Tc26Gost34102012256ParamSetA"
	Tc26Gost34102012256ParamSetB       ID = "Tc26Gost34102012256ParamSetB"
	Tc26Gost34102012256ParamSetC       ID = "Tc26Gost34102012256ParamSetC"
	Tc26Gost34102012256ParamSetD       ID = "Tc26Gost34102012256ParamSetD"
	Tc26Gost34102012512ParamSetA       ID = "Tc26Gost34102012512ParamSetA"
	Tc26Gost34102012512ParamSetB       ID = "Tc26Gost34102012512ParamSetB"
	Tc26Gost34102012512ParamSetC       ID = "Tc26Gost34102012512ParamSetC"
	SignatureGostR34102001             ID = "SignatureGostR34102001"
	SignatureGostR34102001GostR341194  ID = "SignatureGostR34102001GostR341194"
	PublicKeyRSA                       ID = "PublicKeyRSA"
	PublicKeyDSA                       ID = "PublicKeyDSA"
	PublicKeyECDSA                     ID = "PublicKeyECDSA"
	Data                               ID = "Data"
	SignedData                         ID = "SignedData"
	EnvelopedData                      ID = "EnvelopedData"
	SignedAndEnvelopedData             ID = "SignedAndEnvelopedData"
	DigestedData                       ID = "DigestedData"
	EncryptedData                      ID = "EncryptedData"
	AttributeContentType               ID = "AttributeContentType"
	AttributeMessageDigest             ID = "AttributeMessageDigest"
	AttributeSigningTime               ID = "AttributeSigningTime"
	SignatureMD2WithRSA                ID = "SignatureMD2WithRSA"
	SignatureMD5WithRSA                ID = "SignatureMD5WithRSA"
	ISOSignatureSHA1WithRSA            ID = "ISOSignatureSHA1WithRSA"
	SignatureSHA1WithRSA               ID = "SignatureSHA1WithRSA"
	SignatureSHA256WithRSA             ID = "SignatureSHA256WithRSA"
	SignatureSHA384WithRSA             ID = "SignatureSHA384WithRSA"
	SignatureSHA512WithRSA             ID = "SignatureSHA512WithRSA"
	SignatureRSAPSS                    ID = "SignatureRSAPSS"
	SignatureDSAWithSHA1               ID = "SignatureDSAWithSHA1"
	SignatureDSAWithSHA256             ID = "SignatureDSAWithSHA256"
	SignatureECDSAWithSHA1             ID = "SignatureECDSAWithSHA1"
	SignatureECDSAWithSHA256           ID = "SignatureECDSAWithSHA256"
	SignatureECDSAWithSHA384           ID = "SignatureECDSAWithSHA384"
	SignatureECDSAWithSHA512           ID = "SignatureECDSAWithSHA512"
	HashFuncSHA1                       ID = "HashFuncSHA1"
	HashFuncSHA256                     ID = "HashFuncSHA256"
	HashFuncSHA384                     ID = "HashFuncSHA384"
	HashFuncSHA512                     ID = "HashFuncSHA512"
	HashFuncGostR341194                ID = "HashFuncGostR341194"
)

// getList
// en: get a list of constants and asn1.ObjectIdentifier matches
// ru: получить список соответствий констант и asn1.ObjectIdentifier
func getList() map[ID]asn1.ObjectIdentifier {
	return map[ID]asn1.ObjectIdentifier{
		Unknown:                            {0},
		Tc26Gost34102012256:                {1, 2, 643, 7, 1, 1, 1, 1},
		Tc26Gost34102012512:                {1, 2, 643, 7, 1, 1, 1, 2},
		Tc26Gost34112012256:                {1, 2, 643, 7, 1, 1, 2, 2},
		Tc26Gost34112012512:                {1, 2, 643, 7, 1, 1, 2, 3},
		Tc26SignWithDigestGost341012256:    {1, 2, 643, 7, 1, 1, 3, 2},
		Tc26SignWithDigestGost341012512:    {1, 2, 643, 7, 1, 1, 3, 3},
		Tc26AgreementGost341012256:         {1, 2, 643, 7, 1, 1, 6, 1},
		Tc26AgreementGost341012512:         {1, 2, 643, 7, 1, 1, 6, 2},
		GostR34102001CryptoProAParamSet:    {1, 2, 643, 2, 2, 35, 1},
		GostR34102001CryptoProBParamSet:    {1, 2, 643, 2, 2, 35, 2},
		GostR34102001CryptoProCParamSet:    {1, 2, 643, 2, 2, 35, 3},
		GostR34102001CryptoProXchAParamSet: {1, 2, 643, 2, 2, 36, 0},
		GostR34102001CryptoProXchBParamSet: {1, 2, 643, 2, 2, 36, 1},
		Tc26Gost34102012256ParamSetA:       {1, 2, 643, 7, 1, 2, 1, 1, 1},
		Tc26Gost34102012256ParamSetB:       {1, 2, 643, 7, 1, 2, 1, 1, 2},
		Tc26Gost34102012256ParamSetC:       {1, 2, 643, 7, 1, 2, 1, 1, 3},
		Tc26Gost34102012256ParamSetD:       {1, 2, 643, 7, 1, 2, 1, 1, 4},
		Tc26Gost34102012512ParamSetA:       {1, 2, 643, 7, 1, 2, 1, 2, 1},
		Tc26Gost34102012512ParamSetB:       {1, 2, 643, 7, 1, 2, 1, 2, 2},
		Tc26Gost34102012512ParamSetC:       {1, 2, 643, 7, 1, 2, 1, 2, 3},
		SignatureGostR34102001:             {1, 2, 643, 2, 2, 19},
		SignatureGostR34102001GostR341194:  {1, 2, 643, 2, 2, 3},
		PublicKeyRSA:                       {1, 2, 840, 113549, 1, 1, 1},
		PublicKeyDSA:                       {1, 2, 840, 10040, 4, 1},
		PublicKeyECDSA:                     {1, 2, 840, 10045, 2, 1},
		Data:                               {1, 2, 840, 113549, 1, 7, 1},
		SignedData:                         {1, 2, 840, 113549, 1, 7, 2},
		EnvelopedData:                      {1, 2, 840, 113549, 1, 7, 3},
		SignedAndEnvelopedData:             {1, 2, 840, 113549, 1, 7, 4},
		DigestedData:                       {1, 2, 840, 113549, 1, 7, 5},
		EncryptedData:                      {1, 2, 840, 113549, 1, 7, 6},
		AttributeContentType:               {1, 2, 840, 113549, 1, 9, 3},
		AttributeMessageDigest:             {1, 2, 840, 113549, 1, 9, 4},
		AttributeSigningTime:               {1, 2, 840, 113549, 1, 9, 5},
		SignatureMD2WithRSA:                {1, 2, 840, 113549, 1, 1, 2},
		SignatureMD5WithRSA:                {1, 2, 840, 113549, 1, 1, 4},
		ISOSignatureSHA1WithRSA:            {1, 3, 14, 3, 2, 29},
		SignatureSHA1WithRSA:               {1, 2, 840, 113549, 1, 1, 5},
		SignatureSHA256WithRSA:             {1, 2, 840, 113549, 1, 1, 11},
		SignatureSHA384WithRSA:             {1, 2, 840, 113549, 1, 1, 12},
		SignatureSHA512WithRSA:             {1, 2, 840, 113549, 1, 1, 13},
		SignatureRSAPSS:                    {1, 2, 840, 113549, 1, 1, 10},
		SignatureDSAWithSHA1:               {1, 2, 840, 10040, 4, 3},
		SignatureDSAWithSHA256:             {2, 16, 840, 1, 101, 3, 4, 3, 2},
		SignatureECDSAWithSHA1:             {1, 2, 840, 10045, 4, 1},
		SignatureECDSAWithSHA256:           {1, 2, 840, 10045, 4, 3, 2},
		SignatureECDSAWithSHA384:           {1, 2, 840, 10045, 4, 3, 3},
		SignatureECDSAWithSHA512:           {1, 2, 840, 10045, 4, 3, 4},
		HashFuncSHA1:                       {1, 3, 14, 3, 2, 26},
		HashFuncSHA256:                     {2, 16, 840, 1, 101, 3, 4, 2, 1},
		HashFuncSHA384:                     {2, 16, 840, 1, 101, 3, 4, 2, 2},
		HashFuncSHA512:                     {2, 16, 840, 1, 101, 3, 4, 2, 3},
		HashFuncGostR341194:                {1, 2, 643, 2, 2, 9},
	}
}

// GetID
// en: get a constant by the corresponding asn1.ObjectIdentifier
// ru: получить константу по соответствующему asn1.ObjectIdentifier
func GetID(oid asn1.ObjectIdentifier) (ID, error) {
	list := getList()
	for key, item := range list {
		if item.Equal(oid) {
			return key, nil
		}
	}

	return Unknown, ge.Pin(&ge.NotFoundError{Key: fmt.Sprintf("%#v", oid)})
}

// Get
// en: get asn1.ObjectIdentifier by the corresponding constant
// ru: получить asn1.ObjectIdentifier по соответствующей константе
func Get(oidId ID) (asn1.ObjectIdentifier, error) {
	list := getList()

	result, found := list[oidId]
	if !found {
		return nil, ge.Pin(&ge.NotFoundError{Key: string(oidId)})
	}

	return result, nil
}
