package cpu

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

type Seg uint16
type Off uint16

type SegOffset struct {
	Seg Seg
	Off uint16
}

func Reg(mu uc.Unicorn, reg int) uint64 {
	res, err := mu.RegRead(reg)
	if err != nil {
		panic(err)
	}
	return res
}

func Reg8(mu uc.Unicorn, reg int) uint8 {
	res, err := mu.RegRead(reg)
	if err != nil {
		panic(err)
	}
	return uint8(res)
}

func Reg16(mu uc.Unicorn, reg int) uint16 {
	res, err := mu.RegRead(reg)
	if err != nil {
		panic(err)
	}
	return uint16(res)
}

func SReg16(mu uc.Unicorn, reg int) Seg {
	res, err := mu.RegRead(reg)
	if err != nil {
		panic(err)
	}
	return Seg(res)
}

func SetCarryFlag(mu uc.Unicorn, flag bool) error {
	f, err := mu.RegRead(uc.X86_REG_FLAGS)
	if err != nil {
		return err
	}

	if flag {
		f &^= 1
	} else {
		f |= 1
	}
	return mu.RegWrite(uc.X86_REG_FLAGS, f)
}

func Mem16(mu uc.Unicorn, addr uint64) (uint16, error) {
	bm, err := mu.MemRead(addr, 2)
	if err != nil {
		return 0, err
	}
	m := binary.LittleEndian.Uint16(bm)
	return m, nil
}

func PutMem16(mu uc.Unicorn, addr uint64, value uint16) error {
	bm := make([]byte, 2)
	binary.LittleEndian.PutUint16(bm, value)

	return mu.MemWrite(addr, bm)
}

func Mem8(mu uc.Unicorn, addr uint64) (uint8, error) {
	bm, err := mu.MemRead(addr, 1)
	if err != nil {
		return 0, err
	}
	return bm[0], nil
}

func PutMem8(mu uc.Unicorn, addr uint64, value uint8) error {
	bm := []byte{value}
	return mu.MemWrite(addr, bm)
}

func Addr(seg Seg, off uint16) uint64 {
	return uint64(seg*0x10) + uint64(off)
}

func Mem(mu uc.Unicorn, seg Seg, off uint16, size uint64) ([]byte, error) {
	a := Addr(seg, off)
	glog.V(2).Infof("Mem read at address: [%04X] [%04x:%04x]\n", a, seg, off)
	return mu.MemRead(a, size)
}

// Linear Memory fetch
func Meml(mu uc.Unicorn, addr, size uint64) ([]byte, error) {
	glog.V(2).Infof("Mem read at address: [%04X]", addr)
	return mu.MemRead(addr, size)
}

func Push16(mu uc.Unicorn, val uint16) error {
	ss := SReg16(mu, uc.X86_REG_SS)
	sp := Reg16(mu, uc.X86_REG_SP)
	if err := PutMem16(mu, Addr(ss, sp), val); err != nil {
		return err
	}
	return mu.RegWrite(uc.X86_REG_SP, uint64(sp-2))
}

func Push8(mu uc.Unicorn, val uint8) error {
	ss := SReg16(mu, uc.X86_REG_SS)
	sp := Reg16(mu, uc.X86_REG_SP)
	if err := PutMem8(mu, Addr(ss, sp), val); err != nil {
		return err
	}
	return mu.RegWrite(uc.X86_REG_SP, uint64(sp-1))
}

func PushFlags(mu uc.Unicorn) error {
	flags := Reg16(mu, uc.X86_REG_FLAGS)
	return Push16(mu, flags)
}

func PopFlags(mu uc.Unicorn) (uint16, error) {
	return Pop16(mu)
}

func Pop16(mu uc.Unicorn) (uint16, error) {
	ss := SReg16(mu, uc.X86_REG_SS)
	sp := Reg16(mu, uc.X86_REG_SP)
	val, err := Mem16(mu, Addr(ss, sp))
	if err != nil {
		return 0, err
	}
	return val, mu.RegWrite(uc.X86_REG_SP, uint64(sp+2))
}

func Pop8(mu uc.Unicorn) (uint8, error) {
	ss := SReg16(mu, uc.X86_REG_SS)
	sp := Reg16(mu, uc.X86_REG_SP)
	val, err := Mem8(mu, Addr(ss, sp))
	if err != nil {
		return 0, err
	}
	return val, mu.RegWrite(uc.X86_REG_SP, uint64(sp+1))
}

func Jump(mu uc.Unicorn, seg Seg, offset uint16) error {
	if err := mu.RegWrite(uc.X86_REG_CS, uint64(seg)); err != nil {
		// Should we panic() here?
		return err
	}
	return mu.RegWrite(uc.X86_REG_IP, uint64(offset))
}

func MemSegOff(mu uc.Unicorn, seg Seg, off uint16) (SegOffset, error) {
	ioff, err := Mem16(mu, Addr(seg, off))
	if err != nil {
		return SegOffset{}, fmt.Errorf("error reading interrupt segment: %s", err)
	}
	iseg, err := Mem16(mu, Addr(seg, off+2))
	if err != nil {
		return SegOffset{}, fmt.Errorf("error reading interrupt offset: %s", err)
	}
	return SegOffset{
		Seg: Seg(iseg),
		Off: ioff,
	}, nil
}
