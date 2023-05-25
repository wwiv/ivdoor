package cpu

import (
	"encoding/binary"

	"github.com/golang/glog"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

type Seg uint16
type Off uint16

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
