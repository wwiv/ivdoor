package core

import (
	"fmt"

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
	// 	fmt.Printf("Block: 0x%x, 0x%x\n", addr, size)
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
		fmt.Printf("Code: 0x%x, 0x%x; Instruction: '%s'\n", addr, size, inst)

	}, 1, 0)

	mu.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
		atype := "read"
		if access == uc.MEM_WRITE {
			atype = "write"
		}
		fmt.Printf(": Mem %s @0x%x, 0x%x = 0x%x\n", atype, addr, size, value)
	}, 1, 0)

	invalid := uc.HOOK_MEM_READ_INVALID | uc.HOOK_MEM_WRITE_INVALID | uc.HOOK_MEM_FETCH_INVALID
	mu.HookAdd(invalid, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
		atype := "unknown memory error"
		switch access {
		case uc.MEM_WRITE_UNMAPPED | uc.MEM_WRITE_PROT:
			atype = "invalid write"
		case uc.MEM_READ_UNMAPPED | uc.MEM_READ_PROT:
			atype = "invalid read"
		case uc.MEM_FETCH_UNMAPPED | uc.MEM_FETCH_PROT:
			atype = "invalid fetch"
		}
		fmt.Printf("%s: @0x%x, 0x%x = 0x%x\n", atype, addr, size, value)
		return false
	}, 1, 0)

	return nil
}

func allocEmulatorMemory(em Emulator, mu uc.Unicorn) error {
	// Map main memory region 0x07E0:0000 through 0xA000:0000
	if err := mu.MemMap(IVDOOR_MEMORY_MAIN_START, IVDOOR_MEMORY_MAIN_SIZE); err != nil {
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
		e.Handle(mu, intno)
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

func (em Emulator) Start() error {
	return em.mu.Start(IVDOOR_MEMORY_MAIN_START+0x100,
		uint64(IVDOOR_MEMORY_MAIN_START+IVDOOR_MEMORY_MAIN_SIZE))
}
