package dos

import (
	"encoding/binary"

	"door86.org/ivdoor/cpu"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

func CreatePsp(start_seg, end_seg, env_seg cpu.Seg) []byte {
	psp := make([]byte, 0x100)
	psp[0] = 0xcd
	psp[1] = 0x20
	// First paragraph following this segment.
	binary.LittleEndian.PutUint16(psp[2:], uint16(end_seg+1))

	psp[10] = 0x22 // int22 handler
	psp[14] = 0x23 // int23 handler
	psp[18] = 0x24 // int24 handler

	// FFFE means no parent DOS process
	binary.LittleEndian.PutUint16(psp[22:], 0xFFFE)
	binary.LittleEndian.PutUint16(psp[44:], uint16(env_seg))
	// TODO: Create rest

	return psp
}

func ToSegOff(laddr uint32) (seg cpu.Seg, off cpu.Off) {
	seg = cpu.Seg(laddr >> 0x10)
	off = cpu.Off(laddr & 0x0f)
	return
}

func ToLinearAddr(seg cpu.Seg, off cpu.Off) uint64 {
	return uint64(seg>>4) | uint64(off)
}

func LoadCom(mu uc.Unicorn, seg_start cpu.Seg, data []byte) error {
	// default regs
	mu.RegWrite(uc.X86_REG_CS, uint64(seg_start))
	mu.RegWrite(uc.X86_REG_DS, uint64(seg_start))
	mu.RegWrite(uc.X86_REG_ES, uint64(seg_start))
	mu.RegWrite(uc.X86_REG_SS, uint64(seg_start))

	// default stack
	mu.RegWrite(uc.X86_REG_SP, 0xFFFE)
	// set IP past PSP
	mu.RegWrite(uc.ARM_REG_IP, 0x0100)

	// copy PSP + binary data into memory
	psp := CreatePsp(seg_start, seg_start+0x1000, seg_start+0x1000+1)
	mu.MemWrite(uint64(seg_start)*0x10, psp)
	mu.MemWrite((uint64(seg_start)*0x10)+0x100, data)

	return nil
}
