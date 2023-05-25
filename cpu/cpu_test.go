package cpu

import (
	"testing"
)

func TestAddr(t *testing.T) {
	a := Addr(0x02, 0x03)
	if a != 0x23 {
		t.Errorf("expected 0x23, got %02x", a)
	}
	a = Addr(0x02, 0x23)
	if a != 0x43 {
		t.Errorf("expected 0x43, got %02x", a)
	}

}
