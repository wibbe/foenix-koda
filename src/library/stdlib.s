
    include "library.s"


SYS_EXIT              = $00
SYS_INT_REGISTER      = $02
SYS_INT_ENABLE        = $03
SYS_INT_DISABLE       = $04
SYS_CHAN_READ         = $10
SYS_CHAN_READ_B       = $11
SYS_CHAN_WRITE        = $13
SYS_CHAN_WRITE_B      = $14
SYS_KEYBOARD_SCANCODE = $53

SYS_STDOUT             = $00


    org     $0

library_header:
    ; Functions in the library
    function "syscall0", syscall0, 1
    function "syscall1", syscall1, 2
    function "syscall2", syscall2, 3
    function "syscall3", syscall3, 4
    function "syscall4", syscall4, 5

    function "sys_exit", sys_exit, 0
    function "sys_int_enable", sys_int_enable, 1
    function "sys_int_disable", sys_int_disable, 1
    function "sys_chan_write", sys_chan_write, 3

    function "mem_set", mem_set, 3
    function "mem_scan", mem_scan, 3
    function "mem_copy", mem_copy, 3

    function "print_str", print_str, 1
    function "print_num", print_num, 1

    function "str_length", str_length, 1
    
    function "num_to_decimal", num_to_decimal, 3
    ;function "num_to_hex", num_to_hex, 3

    function "min", min, 2
    function "max", max, 2

    function "heap_reset", heap_reset, 0
    function "heap_alloc", heap_alloc, 1
    
    function "__mul32", mul32s, 0
    function "__div32", div32s, 0
    function "__stdlib_init", __stdlib_init, 2

    ; Signal header end
    dc.b    $00

    align   2




__stdlib_init:
    move.l  (4,sp),d1        ; heap end
    move.l  (8,sp),d0        ; heap start

    lea     __heap_start(pc),a0
    move.l  d0,(a0)

    lea     __heap_ptr(pc),a0
    move.l  d0,(a0)

    lea     __heap_end(pc),a0
    move.l  d1,(a0)

    rts

syscall0:
    move.l (4,sp),d0
    trap #15
    move.l d0,d7
    rts

syscall1:
    move.l (4,sp),d1
    move.l (8,sp),d0
    trap #15
    move.l d0,d7
    rts

syscall2:
    move.l (4,sp),d2
    move.l (8,sp),d1
    move.l (12,sp),d0
    trap #15
    move.l d0,d7
    rts

syscall3:
    move.l (4,sp),d3
    move.l (8,sp),d2
    move.l (12,sp),d1
    move.l (16,sp),d0
    trap #15
    move.l d0,d7
    rts

syscall4:
    move.l (4,sp),d4
    move.l (8,sp),d3
    move.l (12,sp),d2
    move.l (16,sp),d1
    move.l (20,sp),d0
    trap #15
    move.l d0,d7
    rts


;
; Quit application and return back to system
; 
sys_exit:
    move.l  #SYS_EXIT,d0
    trap    #15
    rts


sys_int_enable:
    move.l  #SYS_INT_ENABLE,d0
    move.l  (4,sp),d1
    trap    #15
    move.l  d0,d7
    rts

sys_int_disable:
    move.l  #SYS_INT_DISABLE,d0
    move.l  (4,sp),d1
    trap    #15
    move.l  d0,d7
    rts


;
; Write data to a specified channel
; sys_chan_write(channel, data, len)
;
sys_chan_write:
    move.l  #SYS_CHAN_WRITE,d0
    move.l  (12,sp),d1               ; channel
    move.l  (8,sp),d2                ; data
    move.l  (4,sp),d3                ; len
    trap    #15
    move.l  d0,d7
    rts

;
; Fill a memory range with the spcified value
;
mem_set:
    move.l  (4,sp),d1            ; copy length
    move.l  (8,sp),d2            ; copy value to set to
    move.l  (12,sp),a0           ; copy pointer to byte data
.loop:
    move.b  d2,(a0)+
    dbra    d1,.loop
    rts


;
; Try to locate a specific byte value in a memory range
;
mem_scan:
    move.l  (4,sp),d1            ; copy length
    move.l  (8,sp),d2            ; copy byte to search for
    move.l  (12,sp),a0           ; copy pointer to byte data
    move.l  a0,a1                ; copy start address to our iterator
    move.l  a0,a2                ; calculate end position
    add.l   d1,a2                 ; 
.loop:
    cmp.l   a1,a2                 ; are we at the end yet?
    beq     .no_result

    clr.l   d3
    move.b  (a1)+,d3             ; fetch next byte to check
    cmp.l   d3,d2                 ; have we found the byte we are looking for?
    beq     .found_byte
    bra     .loop                   ; loop back

.found_byte:
    move.l  a1,d7                ; move iterator to return register
    sub.l   a0,d7                 ; subtract start position from iterator to get byte position
    subq.l  #1,d7                ; take into account that iterator as been moved to next char
    rts

.no_result:
    move.l  #-1,d7               ; return negative value if byte was not found
    rts



;
; Copy a region of memory into another one.
;
mem_copy:
    move.l  (12,sp),a0           ; fetch destination pointer
    move.l  (8,sp),a1            ; fetch source pointer
    move.l  (4,sp),d1            ; fetch byte count to copy
.mem_copy_loop:
    move.b  (a1)+,(a0)+
    dbra    d1,.mem_copy_loop
    rts


;
; Print a string to standard out
; print_str(str)
;
print_str:
    move.l  #SYS_CHAN_WRITE,d0
    move.l  #SYS_STDOUT,d1
    move.l  (4,sp),d2

    ; Calculate length of string
    move.l  d2,a0
    bsr     _str_length

    move.l  d7,d3

    trap    #15
    move.l  d7,d0
    rts


;
; Print a number to standard out
; print_num(num)
;
print_num:
    move.l  (4,sp),d0

    ; Start by converting the number to a string
    lea     __buffer(pc),a0
    move.l  #32,d1
    bsr     _num_to_decimal

    ; Write string to standard out channel
    move.l  #SYS_CHAN_WRITE,d0
    move.l  #SYS_STDOUT,d1
    lea     __buffer(pc),a0
    move.l  a0,d2
    move.l  d7,d3
    trap    #15

    ; Return zero
    moveq   #0,d7
    rts


;
; Calculate the length of a zero-terminated string
;
str_length:
    move.l  (4,sp),a0
_str_length:
    move.l  a0,d7

.loop:
    tst.b   (a0)+
    bne     .loop

    sub.l   a0,d7
    not.l   d7
    rts

;
; Convert a number to a decimal string, returns the length of the generated string
;
num_to_decimal:
    move.l  (4,sp),d0        ; value to convert
    move.l  (8,sp),a0        ; pointer to string
    move.l  (12,sp),d1       ; length of output string
_num_to_decimal:

    ; If the number is not negative we can treat it as an unsigned value
    btst    #31,d0
    beq.s   num_to_decimal_unsigned

    neg.l   d0              ; negate the value

    ; If the given string is a nullptr we can not add a negative sign
    exg     d0,a0
    tst.l   d0
    exg     d0,a0
    beq.s   .calculate_length

    ; Add char '-' to the front of the string
    move.b  #'-',(a0)+
    subq    #1,d1

.calculate_length:
    bsr.w   num_to_decimal_unsigned
    addq    #1,d0                       ; we need to acount for the extra '-' char in the final string
    beq.s   .error                      ; if we had an error we need to subtract 1
    move.l  d0,d7
    rts

.error:
    subq    #1,d0
    move.l  d0,d7
    rts

num_to_decimal_unsigned:
    ; Calculate pointer to end of buffer, store in a1
    move.l  a0,a1
    add.l   d1,a1

    lea number_to_char(pc),a3       ; a3 - pointer to number_to_char data
    move.l  #32,d1
    sub.l   d1,sp                   ; allocate room on the stack for 32 characters
    move.l  sp,a2                   ; a2 points to the start of the allocated space on the stack

.convert_loop:
    move.l  #10,d1                   ; use base 10
    bsr.w   div32u

    move.b  0(a3,d1.w),(a2)+        ; fetch byte from number_to_char base on remainder from div, and place it on the stack

    tst.l   d0                      ; have we converted the number yet?
    bne.s   .convert_loop

    ; Calculate the length of the final string and store in d0 and d1
    move.l  a2,d0
    sub.l   sp,d0
    move.l  d0,d1

.copy_string:
    cmp.l   a0,a1                   ; have we reach the end of the given string?
    ble.s   .done
    move.b  -(a2),(a0)+             ; move character from stack into given string
    sub.l   #1,d1
    bne.s   .copy_string

    ; TODO: We should zero-terminate the string here

.done:
    ; Deallocate space on the stack
    move.l  #32,d1
    add.l   d1,sp

    move.l  d0,d7                   ; copy string length into the return value register
    rts



;
; Convert a number to a hexidecimal string (base 16)
;
num_to_hex:
    move.l (4,sp),d0        ; value to convert
    move.l (8,sp),a0        ; pointer to string
    move.l (12,sp),d1       ; length of output string
    rts


;
; Returns the smaller number of the two given
; min(a, b)
;
min:
    move.l (4,sp),d1
    move.l (8,sp),d2
    cmp d1,d2
    ble .min_d2         ; d1 >= d2
    move.l d1,d7
    bra .min_done
.min_d2:
    move.l d2,d7
.min_done:
    rts

;
; Returns the larger number of the two given
; max(a, b)
;
max:
    move.l (4,sp),d1
    move.l (8,sp),d2
    cmp d1,d2
    ble .max_d1         ; d1 >= d2
    move.l d2,d7
    bra .max_done
.max_d1:
    move.l d1,d7
.max_done:
    rts



;
; Reset the heap back to the start, freeing all allocated data
;
heap_reset:
    lea     __heap_start(pc),a0
    lea     __heap_ptr(pc),a1
    move.l  a0,(a1)
    rts


;
; Allocate memory on the heap.
; heap_alloc(size)
;
heap_alloc:
    move.l  (4,sp),d0           ; size to allocate
    lea     __heap_ptr(pc),a0
    lea     __heap_end(pc),a1

    move.l  (a0),d7             ; result pointer

    ; Divide size by 4, add 1 and multiply by 4 to get the word aligned size
    ; size = ((size >> 2) + 1) << 2
    lsr.l   #2,d0               ; divide by 4
    addq.l  #1,d0               ; add 1
    lsl.l   #2,d0               ; multiply by two

    ; Calculate size of heap (__heap_end - __heap_ptr)
    move.l  (a1),d1             ; get end of heap
    sub.l   d7,d1

    ; Make sure we have room on the heap
    cmp.l   d0,d1               ; compare requested size vs actual size
    blt     .no_room_on_heap

    ; Add size bytes to __heap_ptr
    add.l   d7,d0
    move.l  d0,(a0)
    rts

.no_room_on_heap:
    moveq   #0,d7               ; return null pointer if we can't allocate
    rts


mul32s:
    move.l  d2,-(sp)

    move.l  d0,-(sp)    ; a
    mulu.w  d1,d0       ; d0=al*bl
    move.l  d1,d2       ; b
    mulu.w  (sp)+,d1    ; d1=ah*bl
    swap    d2          ; d2=bh
    mulu.w  (sp)+,d2    ; d2=al*bh
    add.w   d2,d1
    swap    d1
    move.l  (sp)+,d2
    clr.w   d1
    add.l   d1,d0

    rts 


div32s:
    tst.l   d0
    bpl.s   .numpos
    neg.l   d0
    tst.l   d1
    bpl.s   .denompos
    neg.l   d1
    bsr.s   div32u
    neg.l   d1
    rts

.denompos:
    bsr.s   div32u
    neg.l   d0
    neg.l   d1
    rts

.numpos:
    tst.l   d1
    bpl.s   div32u
    neg.l   d1
    bsr.s   div32u
    neg.l   d0
    rts


div32u:
    move.l  d1,-(sp)
    tst.w   (sp)+       ; can we do this easily? (is number < 65536)
    bne.s   .bigdenom   ; no, we have to work for it
    swap.w  d0
    move.w  d0,d1
    beq.s   .smallnum
    divu.w  (sp),d1
    move.w  d1,d0

.smallnum:
    swap.w  d0
    move.w  d0,d1
    divu.w  (sp)+,d1
    move.w  d1,d0
    clr.w   d1
    swap    d1
    rts

.bigdenom:
    move.w  d2,(sp)
    move.l  d3,-(sp)
    moveq   #15,d3      ; 16 times through the loop
    move.w  d3,d2
    exg     d3,d1       ; d3 is set
    swap    d0          ; $56781234
    move.w  d0,d1       ; $00001234
    clr.w   d0          ; $56780000

.dmls:
    add.l   d0,d0
    addx.l  d1,d1
    cmp.l   d1,d3
    bhi.s   .dmle
    sub.l   d3,d1
    addq.w  #1,d0

.dmle:
    dbf     d2,.dmls

    move.l  (sp)+,d3
    move.w  (sp)+,d2

    rts 




number_to_char:
    dc.b    '0123456789ABCDEF',0

    align   2

__buffer:
    ds.b    32
__heap_ptr:
    dc.l    0
__heap_start:
    dc.l    0
__heap_end:
    dc.l    0