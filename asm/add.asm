; 16-bit COM file example
; nasm add.asm -fbin -o add.com
; to run in MS DOS / DosBox: add.com
  org 100h 
 
section .text 
 
start:
  ; program code
  mov  al, [cr]
  add  al, [lf]
  mov  [xx], al
  cmp  al, 0x17
  jne  end
  xor ax, ax

end: 
  int 20h
 
section .data
  ; program data
 
  cr db 0x0d
  lf db 0x0a
  xx db 0x00
 
section .bss
  ; uninitialized data

