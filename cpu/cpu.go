package cpu

import uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

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
