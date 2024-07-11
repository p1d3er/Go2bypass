package Public

import (
	Go2gabh "Go2bypass/Doge-Gabh/Gabh"
	"Go2bypass/Doge-Gabh/eggreplace"
	"fmt"
	"reflect"
	"unsafe"
)

func Peels() {
	sleep1, e := Go2gabh.MemHgate("84804f99e2c7ab8aee611d256a085cf4879c4be8", Str2sha1)
	if e != nil {
		panic(e)
	}
	times := -(1000 * 10000)
	eggreplace.FindAndReplace(
		[]byte{0x65, 0x67, 0x67, 0x63, 0x61, 0x6c, 0x6c},
		[]byte{0x90, 0x90, 0x0f, 0x05, 0x90, 0x90, 0x90},
		reflect.ValueOf(Go2gabh.EggCall).Pointer())
	fmt.Printf("%s: %x\n", " Sysid", sleep1)
	Go2gabh.HgSyscall(sleep1, 0, uintptr(unsafe.Pointer(&times)))
	fmt.Printf("%s: %x\n", " Sysid", sleep1)
	Go2gabh.EggCall(sleep1, 0, uintptr(unsafe.Pointer(&times)))
}
