package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"door86.org/ivdoor/core"
	"door86.org/ivdoor/dos"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

// Hello
//"ba0c01b409cd21cd2000000048656c6c6f20776f726c640d0a24",
// Add
//"a0140102061501a216013c17750231c0cd2000000d0a00",

var (
	cmdRun  = flag.NewFlagSet("run", flag.ExitOnError)
	cmdInst = flag.NewFlagSet("inst", flag.ExitOnError)
)

func run(b []byte) error {
	// set up unicorn instance and add hooks
	mu, err := uc.NewUnicorn(uc.ARCH_X86, uc.MODE_16)
	if err != nil {
		return err
	}

	// Create emulator
	emu, err := core.NewEmulator(mu)
	if err != nil {
		return err
	}
	emu.Verbose = 4
	d := dos.NewDos(mu, emu.StartSegment(), emu.EndSegment())

	// attach interrupts 0x20 and 0x21
	emu.Register(0x20, d.Int20)
	emu.Register(0x21, d.Int21)

	if err := dos.LoadCom(mu, emu.StartSegment(), b); err != nil {
		return err
	}

	if err := emu.Start(); err != nil {
		return err
	}

	return nil
}

func ReadFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	b, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	if len(b) < 12 {
		return nil, errors.New("File header too small or size unknown for: " + filename)
	}

	return b, nil
}

func showHelp() {
	fmt.Println(`
ivdoor is a tools for executing 8086 Code.

Usage:
ivdoor [arguments] <command> [command arguments]
The commands are:
	inst        Execute a string of opcodes
	run         Execute a DOS executable (exe, com, or binary image)
	help        Displays help
		
Program arguments:
	`)
	flag.PrintDefaults()
}

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		showHelp()
		os.Exit(1)
	}

	args := flag.Args()
	switch args[0] {
	case "run":
		cmdRun.Parse(args[1:])
		if cmdRun.NArg() < 1 {
			fmt.Print("ivdoor\n\nUsage: ivdoor run <dos .com file>.\n")
			showHelp()
			os.Exit(1)
		}
		file := cmdRun.Arg(0)
		b, err := ReadFile(file)
		if err != nil {
			fmt.Println(err)
			return
		}
		run(b)
	case "inst":
		cmdInst.Parse(args[1:])
		if cmdInst.NArg() < 1 {
			fmt.Print("ivdoor\n\nUsage: ivdoor inst <HEX encoded instructions>.\n")
			showHelp()
			os.Exit(1)
		}
		raw := cmdInst.Arg(0)
		b, err := hex.DecodeString(raw)
		if err != nil {
			fmt.Println(err)
			return
		}
		run(b)
	}
}
