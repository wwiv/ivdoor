package bios

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"door86.org/ivdoor/cpu"
	"github.com/golang/glog"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

type Bios struct {
	mu  uc.Unicorn
	in  *bufio.Reader
	out *bufio.Writer
}

func NewBios(mu uc.Unicorn, start, end cpu.Seg) *Bios {
	b := &Bios{
		mu:  mu,
		in:  bufio.NewReader(os.Stdin),
		out: bufio.NewWriter(os.Stdout),
	}

	return b
}

func (bios Bios) Int1A(mu uc.Unicorn, intrNum uint32) error {
	ah := cpu.Reg8(mu, uc.X86_REG_AH)
	//	bx := cpu.Reg16(mu, uc.X86_REG_BX)
	//	cx := cpu.Reg16(mu, uc.X86_REG_CX)
	//	dx := cpu.Reg16(mu, uc.X86_REG_DX)
	cs := cpu.SReg16(mu, uc.X86_REG_CS)
	ds := cpu.SReg16(mu, uc.X86_REG_DS)
	es := cpu.SReg16(mu, uc.X86_REG_ES)
	ss := cpu.SReg16(mu, uc.X86_REG_SS)
	ip := cpu.SReg16(mu, uc.X86_REG_IP)
	sp := cpu.SReg16(mu, uc.X86_REG_SP)

	glog.V(1).Infof("Int1A: CS: 0x%04X DS: 0x%04X ES: 0x%04X SS: 0x%04X IP: 0x%04X SP: 0x%04X\n",
		cs, ds, es, ss, ip, sp)

	switch ah {
	case 0x00: // Read System Clock Counter
		loc, _ := time.LoadLocation("America/New_York")
		now := time.Now().In(loc)
		midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
		// Ticks are 18.206 per second and Seconds returns a float with nanos
		d := uint64(now.Sub(midnight).Seconds() * 18.206)

		dx := d & 0xffff
		mu.RegWrite(uc.X86_REG_DX, dx)
		cx := (d >> 16) & 0xffff
		mu.RegWrite(uc.X86_REG_CX, cx)
	default:
		return fmt.Errorf("unhandled Interrupt 1A subfunction: 0x%02X", ah)
	}
	return nil
}

/*
loc, _ := time.LoadLocation("America/New_York")
now := time.Now().In(loc)
midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
d := now.Sub(midnight)
*/
