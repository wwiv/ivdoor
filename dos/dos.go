package dos

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"door86.org/ivdoor/cpu"
	"github.com/golang/glog"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

type DosFile struct {
	Name string
	Dir  string
	File *os.File
}

type Dos struct {
	mu  uc.Unicorn
	in  *bufio.Reader
	out *bufio.Writer

	// DOS file handles
	files map[int]*DosFile
}

func NewDos(mu uc.Unicorn) *Dos {
	d := &Dos{
		mu:    mu,
		in:    bufio.NewReader(os.Stdin),
		out:   bufio.NewWriter(os.Stdout),
		files: make(map[int]*DosFile),
	}
	d.files[0] = &DosFile{Name: "", Dir: "", File: os.Stdin}
	d.files[1] = &DosFile{Name: "", Dir: "", File: os.Stdout}
	d.files[2] = &DosFile{Name: "", Dir: "", File: os.Stderr}

	return d
}

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

func ToSegOff(laddr uint32) (seg cpu.Seg, off uint16) {
	seg = cpu.Seg(laddr >> 0x10)
	off = uint16(laddr & 0x0f)
	return
}

func ToLinearAddr(seg cpu.Seg, off uint16) uint64 {
	return uint64(seg<<4) | uint64(off)
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

func (dos Dos) Int20(mu uc.Unicorn, intrNum uint32) error {
	fmt.Println("Int20: Stop")
	mu.Stop()
	return nil
}

func getStringDollarSign(mu uc.Unicorn, seg cpu.Seg, offset uint16) (string, error) {
	var count uint16 = 0
	var buff strings.Builder
	for {
		// dx is offset
		b, err := mu.MemRead(ToLinearAddr(seg, offset+count), 1)
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
		if count >= 0xFFFF {
			// Overflow.
			return "", errors.New("$string size >64k")
		}
	}
}

func GetString(mu uc.Unicorn, seg cpu.Seg, offset uint16) (string, error) {
	var count uint16 = 0
	var buff strings.Builder
	for {
		// dx is offset
		b, err := mu.MemRead(ToLinearAddr(seg, offset+count), 1)
		if err != nil {
			return "", err
		}
		if b[0] == 0 {
			// End of string, print.
			return buff.String(), nil
		}
		// Append
		if _, err := buff.Write(b); err != nil {
			return "", err
		}
		count++
		if count >= 0xFFFF {
			// Overflow.
			return "", errors.New("null-string size >64k")
		}
	}
}

// Sets the carry flag to 1 and AX to errno
// returns a new error with message
func (d Dos) SetDosError(errno uint64, message string) error {
	cpu.SetCarryFlag(d.mu, true)
	d.mu.RegWrite(uc.X86_REG_AX, errno)
	return errors.New(message)
}

// Sets the carry flag to 0 and ax to the specified value and returns
// a nil error
func (d Dos) ClearDosError(ax uint64) error {
	cpu.SetCarryFlag(d.mu, false)
	d.mu.RegWrite(uc.X86_REG_AX, ax)
	return nil
}

func (d Dos) GetNextFreeHandle() (int, error) {
	for handle := 3; handle < 200; handle++ {
		if _, ok := d.files[handle]; !ok {
			return handle, nil
		}
	}
	return 0, errors.New("no file handles available")
}

func dosFileModeToGo(ah uint8) (int, os.FileMode) {
	mode := 0
	switch mode & 0x3 {
	case 0:
		mode = os.O_RDONLY
	case 1:
		mode = os.O_WRONLY
	case 2:
		mode = os.O_RDWR
	}
	// mode = mode >> 4
	// var perm os.FileMode = 0
	// switch mode & 0x07 {}
	// TODO - Implement sharing
	return mode, 755
}

// https://stanislavs.org/helppc/int_21.html
func (d *Dos) Int21(mu uc.Unicorn, intrNum uint32) error {
	ah := cpu.Reg8(mu, uc.X86_REG_AH)
	al := cpu.Reg8(mu, uc.X86_REG_AL)
	bx := cpu.Reg16(mu, uc.X86_REG_BX)
	cx := cpu.Reg16(mu, uc.X86_REG_CX)
	dx := cpu.Reg16(mu, uc.X86_REG_DX)
	ds := cpu.SReg16(mu, uc.X86_REG_DS)

	switch ah {

	case 0x00: // terminate process
		fmt.Println("Int21: 0x0 Stop")
		mu.Stop()

	case 0x01: // Keyboard Input with Echo
		c, err := d.in.ReadByte()
		if err != nil {
			mu.RegWrite(uc.X86_REG_AH, uint64(c))
		}

	case 0x02: // Display Output
		d.out.WriteByte(byte(dx & 0xff))
	case 0x09: // Print $ terminated string.
		if s, err := getStringDollarSign(mu, ds, dx); err == nil {
			fmt.Print(s)
		}
	case 0x0a: // Buffered Keyboard Input
		reader := bufio.NewReader(d.in)
		bmax, _ := mu.MemRead(ToLinearAddr(ds, dx), 1)
		max := int(bmax[0])
		message, _ := reader.ReadString('\n')
		if len(message) >= max {
			message = message[:max-1]
		}
		mu.MemWrite(ToLinearAddr(ds, dx), []byte{bmax[0], byte(len(message))})
		mu.MemWrite(ToLinearAddr(ds, dx)+2, []byte(message))
	case 0x30: // Get DOS Version Number
		mu.RegWrite(uc.X86_REG_AX, 0x07)

	case 0x3c: // Create File Using Handle
		filename, err := GetString(mu, ds, dx)
		if err != nil {
			// 	57  Invalid parameter
			return d.SetDosError(0x57, "filename missing")
		}
		handle, err := d.GetNextFreeHandle()
		if err != nil {
			// Set error to 04  Too many open files (no handles left)
			return d.SetDosError(0x04, "unable to allocate file handle")
		}
		f, err := os.Create(filename)
		if err != nil {
			return d.SetDosError(0x1F, "create file failed")
		}
		// Success
		d.files[handle] = &DosFile{
			Name: filename,
			Dir:  "",
			File: f,
		}
		return d.ClearDosError(uint64(handle))

	case 0x3d: // Open File Using Handle
		filename, err := GetString(mu, ds, dx)
		if err != nil {
			// 	57  Invalid parameter
			return d.SetDosError(0x57, "filename missing")
		}

		handle, err := d.GetNextFreeHandle()
		if err != nil {
			// Set error to 04  Too many open files (no handles left)
			return d.SetDosError(0x04, "unable to allocate file handle")
		}

		flag, perm := dosFileModeToGo(al)
		f, err := os.OpenFile(filename, flag, perm)
		if err != nil {
			return d.SetDosError(0x02, "open file failed")
		}
		// Success
		d.files[handle] = &DosFile{
			Name: filename,
			Dir:  "",
			File: f,
		}
		return d.ClearDosError(uint64(handle))

	case 0x3E: // Close File Using Handle
		file, ok := d.files[int(bx)]
		if !ok {
			return d.SetDosError(0x06, fmt.Sprintf("Invalid handle: %d", bx))
		}
		if err := file.File.Close(); err != nil {
			glog.Warningf("Error closing file handle %d: '%s'", bx, err)
		}
		delete(d.files, int(bx))
		return nil

	case 0x3F: // Read From File or Device Using Handle
		file, ok := d.files[int(bx)]
		if !ok {
			return d.SetDosError(0x06, fmt.Sprintf("Invalid handle: %d", bx))
		}
		bytes := make([]byte, cx)
		numRead, err := file.File.Read(bytes)
		if err != nil {
			return d.SetDosError(0x1E, "Read fault")
		}
		mu.MemWrite(ToLinearAddr(ds, dx), bytes)
		return d.ClearDosError(uint64(numRead))

	case 0x40: // Write To File or Device Using Handle
		file, ok := d.files[int(bx)]
		if !ok {
			return d.SetDosError(0x06, fmt.Sprintf("Invalid handle: %d", bx))
		}
		if cx == 0 {
			// CX = number of bytes to write, a zero value truncates/extends
			// the file to the current file position
			pos, err := file.File.Seek(0, io.SeekCurrent)
			if err != nil {
				return d.SetDosError(0x19, "Seek failure")
			}
			return file.File.Truncate(pos)
		}
		mem, err := mu.MemRead(ToLinearAddr(ds, dx), uint64(cx))
		if err != nil {
			return d.SetDosError(0x1f, "General failure")
		}
		numWritten, err := file.File.Write(mem)
		if err != nil {
			return d.SetDosError(0x1D, "write fault")
		}
		return d.ClearDosError(uint64(numWritten))

	case 0x41: // Delete File
		filename, err := GetString(mu, ds, dx)
		if err != nil {
			// 	57  Invalid parameter
			return d.SetDosError(0x57, "filename missing")
		}
		if _, err := os.Stat(filename); err != nil {
			return d.SetDosError(2, "File not found")
		}
		if err := os.Remove(filename); err != nil {
			return d.SetDosError(0x1f, "???")
		}
		return d.ClearDosError(0)

	case 0x42: // Move File Pointer Using Handle
		file, ok := d.files[int(bx)]
		if !ok {
			return d.SetDosError(0x06, fmt.Sprintf("Invalid handle: %d", bx))
		}
		whence := io.SeekCurrent
		switch al {
		case 0:
			whence = io.SeekStart
		case 1:
			whence = io.SeekCurrent
		case 2:
			whence = io.SeekEnd
		}
		num := int64(cx)<<8 | int64(dx)
		pos, err := file.File.Seek(num, whence)
		if err != nil {
			return d.SetDosError(0x19, "Seek failure")
		}
		mu.RegWrite(uc.X86_REG_DX, uint64(pos)>>8)
		return d.ClearDosError(uint64(pos))

	case 0x4c: // Terminate process with return code
		fmt.Println("Int21: 0x0 Stop")
		mu.Stop()

	default:
		fmt.Printf("Int21: Unhandled instrction: 0x%x; AH=0x%x\n", intrNum, ah)
	}

	return nil
}
