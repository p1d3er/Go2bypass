package main

import "fmt"

func main() {
	fmt.Println(string(byte('\x0f')), string(byte('\x05')), string(byte('\xc3')))
}
