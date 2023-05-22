package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"door86.org/ivdoor/core"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

var asm = strings.Join([]string{
	// Hello
	//"ba0c01b409cd21cd2000000048656c6c6f20776f726c640d0a24",
	// Add
	"a0140102061501a216013c17750231c0cd2000000d0a00",
}, "")

func run() error {
	code, err := hex.DecodeString(asm)
	if err != nil {
		return err
	}
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

	// attach interrupts 0x20 and 0x21
	emu.Register(0x20, core.Int20)
	emu.Register(0x21, core.Int21)

	// Start code at 0x100
	if err := emu.Write(0x100, code); err != nil {
		return err
	}

	if err := emu.Start(); err != nil {
		return err
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
	}
}
