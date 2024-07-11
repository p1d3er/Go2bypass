# Go2bypass
Golang 写的免杀框架，通过系统调用等手法bypass AV/EDR

Golang 写的免杀框架，通过系统调用等手法bypass AV/EDR。

此项目2021年写的。好久更新了，刚刚测试一些常见的AV和EDR还是可以绕过的，有兴趣的可以自己改改。

使用方法：

```
D:\Go2bypass>go run Go2bypass.go build
Choose different encryption methods and Windows api for shellcodeloader.

Usage:
  Go2bypass build [flags]

Examples:
go run .\Go2bypass.go build -e Encrypt-modu -f payload.bin -m loader-modu
go run .\Go2bypass.go build -e Encrypt-modu -f payload.bin -m loader-modu --hiddenCMD
go run .\Go2bypass.go build -e Encrypt-modu -f payload.bin -m loader-modu --hiddenCMD -i .ico
go run .\Go2bypass.go build -e Encrypt-modu -f payload.bin -m Syscall
go run .\Go2bypass.go build -e Encrypt-modu -f payload.bin -m HaloGate
go run .\Go2bypass.go build -e Encrypt-modu -f payload.bin -m HeapAlloc
go run .\Go2bypass.go build -e Encrypt-modu -f payload.bin -m UuidFromString
go run .\Go2bypass.go build -e Encrypt-modu -f payload.bin -m EtwpCreateEtwThread
go run .\Go2bypass.go build -e Encrypt-modu -f payload.bin -m EnumPageFilesW
go run .\Go2bypass.go build -e Encrypt-modu -f payload.bin -m EnumChildWindows
go run .\Go2bypass.go build -e Encrypt-modu -f payload.bin -m EnumerateLoadedModules
go run .\Go2bypass.go build -e Encrypt-modu -f payload.bin -m CreateFiber
go run .\Go2bypass.go build -e Encrypt-modu -f payload.bin -m CreateThread
go run .\Go2bypass.go build -e Encrypt-modu -f payload.bin -m CreateThreatPoolWait


Flags:
  -e, --encrypt string   Choose Encryption Method
                             eg:
                                AesCBC
                                AesECB
                                AesCFB
                                Base64Xor
                                QianKunBaGua
  -f, --file string      Specify The Path To The (x64)payload.bin File
  -h, --help             help for build
  -c, --hiddenCMD        Use "go build -ldflags=-H=windowsgui" hiddenCMD Or use Windows Api hidden cmd default:(-ldflags=-H=windowsgui)
  -i, --icon string      Add icon
  -m, --module string    Select The Mode Of The ShellcodeLoader
                             eg:
                                Syscall
                                HaloGate
                                HeapAlloc
                                UuidFromString
                                EtwpCreateEtwThread
                                EnumPageFilesW
                                EnumChildWindows
                                EnumerateLoadedModules
                                CreateFiber
                                CreateThread
                                CreateThreatPoolWait
  -o, --output string    Output FileName
```



```
go run .\Go2bypass.go build -e AesCBC -f payload.bin -m HaloGate
```

