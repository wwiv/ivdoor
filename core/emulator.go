package core

import (
	"encoding/hex"
	"fmt"

	"door86.org/ivdoor/cpu"
	"door86.org/ivdoor/dos"
	"github.com/golang/glog"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"golang.org/x/arch/x86/x86asm"
)

// See http://staff.ustc.edu.cn/~xyfeng/research/cos/resources/machine/mem.htm
const (
	IVDOOR_MEMORY_IVT_START = 0x0000
	IVDOOR_MEMORY_IVT_SIZE  = 0x400 - IVDOOR_MEMORY_IVT_START

	IVDOOR_MEMORY_BIOS_START = 0x400
	IVDOOR_MEMORY_BIOS_SIZE  = 0x500 - IVDOOR_MEMORY_IVT_START

	IVDOOR_MEMORY_MAIN_START = 0x1000 // Should be 0x500 but we need 4k boundary for unicorn.
	// Should be 0x9FC00 but we need 4k boundary for unicorn.
	IVDOOR_MEMORY_MAIN_SIZE = 0x9F000 - IVDOOR_MEMORY_MAIN_START

	IVDOOR_MEMORY_VIDEO_START = 0xA0000
	IVDOOR_MEMORY_VIDEO_SIZE  = 0xC8000 - IVDOOR_MEMORY_VIDEO_START

	IVDOOR_MEMORY_EXTENDED_START = 0x100000
	IVDOOR_MEMORY_EXTENDED_SIZE  = 0xFEC00000 - IVDOOR_MEMORY_EXTENDED_START
)

type InterruptHandler func(mu uc.Unicorn, intrNum uint32) error

type Emulator struct {
	mu      uc.Unicorn
	intrs   map[uint32]InterruptHandler
	Verbose int
}

func addDefaultHooks(mu uc.Unicorn) error {

	// mu.HookAdd(uc.HOOK_BLOCK, func(mu uc.Unicorn, addr uint64, size uint32) {
	// 	glog.V(1).Infof("Block: 0x%x, 0x%x\n", addr, size)
	// }, 1, 0)

	mu.HookAdd(uc.HOOK_CODE, func(mu uc.Unicorn, addr uint64, size uint32) {
		mem, err := mu.MemRead(addr, uint64(size))
		if err != nil {
			fmt.Println(err)
			return
		}
		inst, err := x86asm.Decode(mem, 16)
		if err != nil {
			fmt.Println(err)
			return
		}
		// 0E06:004E BE0010            MOV     SI,1000
		cs := uint64(cpu.Reg16(mu, uc.X86_REG_CS) * 0x10)
		offset := addr - cs
		glog.V(1).Infof("[%04X:%04X] %-12s (size: %2d) Instruction: '%s'\n",
			cs, offset, hex.EncodeToString(mem), size, inst)
		glog.V(4).Infoln()

	}, 1, 0)

	mu.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
		atype := "read"
		if access == uc.MEM_WRITE {
			atype = "write"
		}
		glog.V(1).Infof("Mem %s: @0x%x, 0x%x = 0x%x\n", atype, addr, size, value)
	}, 1, 0)

	invalid := uc.HOOK_MEM_READ_INVALID | uc.HOOK_MEM_WRITE_INVALID | uc.HOOK_MEM_FETCH_INVALID | uc.HOOK_MEM_UNMAPPED
	mu.HookAdd(invalid, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
		atype := "unknown memory error"
		switch access {
		case uc.MEM_WRITE_UNMAPPED | uc.MEM_WRITE_PROT:
			atype = "invalid write"
		case uc.MEM_READ_UNMAPPED | uc.MEM_READ_PROT:
			atype = "invalid read"
		case uc.MEM_FETCH_UNMAPPED | uc.MEM_FETCH_PROT:
			atype = "invalid fetch"
		case uc.HOOK_MEM_UNMAPPED:
			atype = "mem unmapped"
		}
		glog.Errorf("%s: @0x%X, 0x%X = 0x%X\n", atype, addr, size, value)
		return false
	}, 1, 0)

	return nil
}

func allocEmulatorMemory(em Emulator, mu uc.Unicorn) error {
	//IVDOOR_MEMORY_MAIN_START, IVDOOR_MEMORY_MAIN_SIZE
	// Map 1M
	if err := mu.MemMap(0, 0x100000); err != nil {
		return err
	}
	// start emulation
	mu.RegWriteBatch([]int{uc.X86_REG_DS, uc.X86_REG_CS}, []uint64{IVDOOR_MEMORY_MAIN_START / 0x10, IVDOOR_MEMORY_MAIN_START / 0x10})
	return nil
}

func NewEmulator(mu uc.Unicorn) (*Emulator, error) {
	e := Emulator{mu: mu, intrs: make(map[uint32]InterruptHandler), Verbose: 0}
	addDefaultHooks(mu)
	mu.HookAdd(uc.HOOK_INTR, func(mu uc.Unicorn, intno uint32) {
		ah, _ := mu.RegRead(uc.X86_REG_AH)
		if err := e.Handle(mu, intno); err != nil {
			glog.Warningf("Error executing Hook: 0x%x/%x: '%s'\n", intno, ah, err)
		}
	}, 1, 0)
	if err := allocEmulatorMemory(e, mu); err != nil {
		return nil, err
	}
	return &e, nil
}

func (intr *Emulator) Register(num uint32, handler InterruptHandler) error {
	intr.intrs[num] = handler
	return nil
}

func (intr Emulator) Handle(mu uc.Unicorn, intrNum uint32) error {
	if handler, ok := intr.intrs[intrNum]; ok {
		return handler(mu, intrNum)
	}
	// nothing to do.
	return nil
}

func (em Emulator) Write(offset uint64, data []byte) error {
	return em.mu.MemWrite(IVDOOR_MEMORY_MAIN_START+offset, data)
}

func (em Emulator) StartSegment() cpu.Seg {
	return IVDOOR_MEMORY_MAIN_START / 16
}

func (em Emulator) EndSegment() cpu.Seg {
	return (IVDOOR_MEMORY_MAIN_START + IVDOOR_MEMORY_MAIN_SIZE) / 16
}

func (em Emulator) WriteBinary(seg uint16, data []byte) error {
	start := cpu.Seg(IVDOOR_MEMORY_MAIN_START/16 + seg)
	size := len(data)
	if size < 0x10000 {
		size = 0x10000
	}
	len := size >> 4
	end := cpu.Seg(uint16(start) + uint16(len))
	psp := dos.CreatePsp(start, end, end+1, []string{})
	em.mu.MemWrite(uint64(IVDOOR_MEMORY_MAIN_START+seg), psp)
	return em.mu.MemWrite(uint64(IVDOOR_MEMORY_MAIN_START+seg+0x100), data)
}

func (em Emulator) Start() error {
	// Use CS:IP
	cs := cpu.Reg16(em.mu, uc.X86_REG_CS)
	ip := cpu.Reg16(em.mu, uc.X86_REG_IP)

	return em.mu.Start(uint64(cs*0x10+ip),
		uint64(IVDOOR_MEMORY_MAIN_START+IVDOOR_MEMORY_MAIN_SIZE))
}
