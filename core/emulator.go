package core

import (
	"encoding/hex"
	"fmt"

	"door86.org/ivdoor/cpu"
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

func hook_insn_invalid(mu uc.Unicorn) bool {
	cs := cpu.SReg16(mu, uc.X86_REG_CS)
	ip := cpu.Reg16(mu, uc.X86_REG_IP)
	addr := cpu.Addr(cs, ip)
	mem, err := mu.MemRead(addr, 15)
	if err != nil {
		fmt.Println(err)
		return false
	}
	inst, err := x86asm.Decode(mem, 16)
	if err != nil {
		fmt.Println(err)
		return false
	}

	glog.Errorf("Invalid Instruction: '%-15s', '%s'", hex.EncodeToString(mem), inst)

	return false
}

func addDefaultHooks(mu uc.Unicorn) error {

	mu.HookAdd(uc.HOOK_INSN_INVALID, hook_insn_invalid, 1, 0)

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
		// do we need to fix IP?
		csBase := uint64(cpu.Reg16(mu, uc.X86_REG_CS) * 0x10)
		ip := cpu.Reg(mu, uc.X86_REG_EIP)
		eip := cpu.Reg(mu, uc.X86_REG_EIP)
		glog.V(3).Infof("IP: 0x%04X EIP: 0x%04X", ip, eip)
		ip = addr - csBase
		mu.RegWrite(uc.X86_REG_IP, ip)

		if glog.V(2) {
			ax := cpu.Reg8(mu, uc.X86_REG_AX)
			bx := cpu.Reg16(mu, uc.X86_REG_BX)
			cx := cpu.Reg16(mu, uc.X86_REG_CX)
			dx := cpu.Reg16(mu, uc.X86_REG_DX)
			cs := cpu.SReg16(mu, uc.X86_REG_CS)
			ds := cpu.SReg16(mu, uc.X86_REG_DS)
			es := cpu.SReg16(mu, uc.X86_REG_ES)
			ss := cpu.SReg16(mu, uc.X86_REG_SS)
			ip := cpu.Reg16(mu, uc.X86_REG_IP)
			bp := cpu.SReg16(mu, uc.X86_REG_BP)
			sp := cpu.SReg16(mu, uc.X86_REG_SP)

			glog.V(2).Infof("Inst: CS: 0x%04X IP: 0x%04X DS: 0x%04X ES: 0x%04X SS: 0x%04X BP: 0x%04X SP: 0x%04X\n",
				cs, ip, ds, es, ss, bp, sp)
			glog.V(2).Infof("Inst: AX: 0x%04X BX: 0x%04X CX: 0x%04X DX: 0x%04X\n",
				ax, bx, cx, dx)
			glog.V(2).Infof("[%04X:%04X] %-12s (size: %2d) Instruction: '%s'\n",
				cs, ip, hex.EncodeToString(mem), size, inst)
			next, _ := mu.MemRead(addr, 0x80)
			glog.V(4).Infof("Next Memory: %s\n", hex.EncodeToString(next))
			glog.V(4).Infoln()
		}

	}, 1, 0)

	mu.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
		atype := "read"
		if access == uc.MEM_WRITE {
			atype = "write"
		}
		glog.V(3).Infof("Mem %s: @0x%x, 0x%x = 0x%x\n", atype, addr, size, value)
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
	return nil
}

func NewEmulator(mu uc.Unicorn) (*Emulator, error) {
	e := Emulator{mu: mu, intrs: make(map[uint32]InterruptHandler), Verbose: 0}
	addDefaultHooks(mu)
	if err := allocEmulatorMemory(e, mu); err != nil {
		return nil, err
	}
	mu.HookAdd(uc.HOOK_INTR, func(mu uc.Unicorn, intno uint32) {
		ah, _ := mu.RegRead(uc.X86_REG_AH)
		if err := e.Handle(mu, intno); err != nil {
			glog.Warningf("Error executing Hook: 0x%x/%x: \nDetails: '%s'\n", intno, ah, err)
		}
	}, 1, 0)
	return &e, nil
}

func (intr *Emulator) Register(num uint32, handler InterruptHandler) error {
	intr.intrs[num] = handler
	return nil
}

func (intr Emulator) Handle(mu uc.Unicorn, intrNum uint32) error {
	// Look for interrupt handler in the host
	if handler, ok := intr.intrs[intrNum]; ok {
		return handler(mu, intrNum)
	}

	// Use 8086 IDT to find address for guest handler, we could look at
	// our map, but that only works if INT 21, 35h and 25h was used.
	// This also catches apps that write directly.
	so, err := cpu.MemSegOff(intr.mu, cpu.Seg(0), uint16(intrNum*4))
	if err != nil {
		return fmt.Errorf("error reading interrupt address: %s", err)
	}

	// We leave them zero'ed out if there's nothing to do, and we'll simply
	// not ever call these.
	if so.Seg == 0 && so.Off == 0 {
		// nothing to do.
		return fmt.Errorf("unhandled interrupt: %02X", intrNum)
	}

	// Since we're doing the interrupt call, need to do it in the same way
	// 8086 apps expect it.  On the stack we need to push Flags -> CS -> IP
	// The interrupt IRET does the following:
	// EIP := Pop(); (* 16-bit pop; clear upper 16 bits *)
	// CS := Pop(); (* 16-bit pop *)
	// EFLAGS[15:0] := Pop();

	// Push current flags, then CS then IP to the stack.
	cpu.PushFlags(mu)

	cs := cpu.Reg16(mu, uc.X86_REG_CS)
	cpu.Push16(mu, cs)

	ip := cpu.Reg16(mu, uc.X86_REG_IP)
	cpu.Push16(mu, ip)

	// Finally jump to 8086 code address and let the emulation continue.
	return cpu.Jump(mu, cpu.Seg(so.Seg), so.Off)
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

func (em Emulator) Start() error {
	// Use CS:IP
	cs := cpu.SReg16(em.mu, uc.X86_REG_CS)
	ip := cpu.Reg16(em.mu, uc.X86_REG_IP)

	start := cpu.Addr(cs, ip)
	return em.mu.Start(uint64(start), 0xffffffff)
}
