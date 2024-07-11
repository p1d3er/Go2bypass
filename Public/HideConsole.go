package Public

import (
	"syscall"
)

const (
	SW_RESTORE uintptr = 9
	SW_HIDE    uintptr = 0
)

func HideConsole() {
	Hide(false)
}
func Hide(show bool) {
	getWin := syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2'})).NewProc(cusBase64decode("VldwS1YwMUdSWGxQV0ZacVRXcHNlbGRzV210alIwcDBWVzVhYTJSNk1Eaz0="))
	showWin := syscall.NewLazyDLL(string([]byte{'u', 's', 'e', 'r', '3', '2'})).NewProc(cusBase64decode("VmxSS2IyUnRVWGhhU0VKcFlsWktNbHBJWXpsUVVUMDk="))
	hwnd, _, _ := getWin.Call()
	if hwnd == 0 {
		return
	}
	if show {
	} else {
		showWin.Call(uintptr(hwnd), SW_HIDE)
	}
}
