package core

import (
	"errors"
	"fmt"
	"strings"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

func addr(seg, offset uint64) uint64 {
	return seg*16 + offset
}

func GetStringDollarSign(mu uc.Unicorn, seg, offset uint64) (string, error) {
	count := 0
	var buff strings.Builder
	for {
		// dx is offset
		b, err := mu.MemRead(addr(seg, offset), 1)
		offset++
		if err != nil {
			return "", err
		}
		if b[0] == '$' {
			// End of string, print.
			return buff.String(), nil
		}
		// Append
		if _, err := buff.Write(b); err != nil {
			return "", err
		}
		count++
		if count > 0x10000 {
			// Overflow.
			return "", errors.New("$string size >64k")
		}
	}
}

func Int21(mu uc.Unicorn, intrNum uint32) error {
	ah, err := mu.RegRead(uc.X86_REG_AH)
	if err != nil {
		return err
	}
	dx, err := mu.RegRead(uc.X86_REG_DX)
	if err != nil {
		return err
	}
	ds, err := mu.RegRead(uc.X86_REG_DS)
	if err != nil {
		return err
	}

	switch ah {

	case 0x09: // Print $ terminated string.
		if s, err := GetStringDollarSign(mu, ds, dx); err == nil {
			fmt.Print(s)
		}
	default:
		fmt.Printf("Int21: Unhandled instrction: 0x%x; AH=0x%x\n", intrNum, ah)
	}

	return nil
}
