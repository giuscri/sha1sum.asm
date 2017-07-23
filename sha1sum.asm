# Copyright (c) 2017 Giuseppe Crino'
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

.globl main

.globl pad
.globl handle_chunk

.globl hexlify
.globl left_rotate
.globl lw_as_big_endian
.globl sw_as_big_endian

.data
state: .word 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210, 0xf0e1d2c3 
hexlify_map: .ascii "0123456789abcdef"

.text
lw_as_big_endian:
    ###
    # Decode word as a big-endian 4 byte word.
    #
    # Args:
    #   word (int*)
    #
    # Returns:
    #   int: decoded word
    ###

    # cdecl prologue
    sub $sp, $sp, 4
    sw $ra, 0($sp)
    sub $sp, $sp, 4
    sw $fp, 0($sp)
    move $fp, $sp

    # Store addr of word to decode in t0
    lw $t0, 8($fp)

    # return_value = 0
    move $v0, $zero

    # return_value |= *t0
    lbu $t1, 0($t0)
    or $v0, $v0, $t1

    # return_value <<= 8
    sll $v0, $v0, 8

    # return_value |= *(t0+1)
    lbu $t1, 1($t0)
    or $v0, $v0, $t1

    # return_value <<= 8
    sll $v0, $v0, 8

    # return_value |= *(t0+2)
    lbu $t1, 2($t0)
    or $v0, $v0, $t1

    # return_value <<= 8
    sll $v0, $v0, 8

    # return_value |= *(t0+3)
    lbu $t1, 3($t0)
    or $v0, $v0, $t1

    # cdel epilogue
    move $sp, $fp
    lw $fp, 0($sp)
    add $sp, $sp, 4
    lw $ra, 0($sp)
    add $sp, $sp, 4
    jr $ra

sw_as_big_endian:
    ###
    # Encode word as a big-endian 4 byte word.
    #
    # Args:
    #   word (int)
    #   where (int*)
    ###

    # cdecl prologue
    sub $sp, $sp, 4
    sw $ra, 0($sp)
    sub $sp, $sp, 4
    sw $fp, 0($sp)
    move $fp, $sp

    # t0, t1 = word, where
    lw $t0, 8($fp)
    lw $t1, 12($fp)

    # *t1 = t0>>24 & 0xff
    srl $t3, $t0, 24
    and $t3, $t3, 0xff
    sb $t3, 0($t1)

    # *(t1+1) = t0>>16 & 0xff
    srl $t3, $t0, 16
    and $t3, $t3, 0xff
    sb $t3, 1($t1)

    # *(t1+2) = t0>>8 & 0xff
    srl $t3, $t0, 8
    and $t3, $t3, 0xff
    sb $t3, 2($t1)

    # *(t1+3) = t0 & 0xff
    and $t3, $t0, 0xff
    sb $t3, 3($t1)

    # cdecl epilogue
    move $sp, $fp
    lw $fp, 0($sp)
    add $sp, $sp, 4
    lw $ra, 0($sp)
    add $sp, $sp, 4
    jr $ra

pad:
    ###
    # Append bytes to blob following the padding procedure
    # described in RFC3174, tools.ietf.org/html/rfc3174#section-4
    #
    # Args:
    #   blob (char*)
    #   len (int): number of bytes in the blob
    #
    # Returns:
    #
    #   char*, int: address of the padded blob and its length
    ###

    # cdecl prologue
    sub $sp, $sp, 4
    sw $ra, 0($sp)
    sub $sp, $sp, 4
    sw $fp, 0($sp)
    move $fp, $sp

    # Move s0, s1, s2, s3 to memory for later restore
    sub $sp, $sp, 16
    sw $s0, -4($fp)
    sw $s1, -8($fp)
    sw $s2, -12($fp)
    sw $s3, -16($fp)

    # s0, s3 = blob, len
    lw $s0, 8($fp)
    lw $s3, 12($fp)

    # Allocate enough memory to store the padded blob. Length
    # of the padded blob is computed as follows
    #
    #     ((len(blob)+1+8)<<3 + (512 - (len(blob)+1+8)<<3 % 512)) / 8
    #
    # In the above expression, the closer the operator the higher
    # the precedence.
    li $a0, 512
    add $t0, $s3, 9
    sll $t0, $t0, 3
    div $t0, $a0
    mfhi $t0 # t0 = a0 % 512
    sub $a0, $a0, $t0

    add $t0, $s3, 9
    sll $t0, $t0, 3
    add $a0, $a0, $t0
    srl $a0, $a0, 3
    li $v0, 9
    syscall
    move $s2, $v0 # s2 = malloc(a0)

    # Copy the untouched blob to a larger space
    # such to have room for the later padding.
    li $s1, 0 # int i=0;
    copy_blob_loop:
        beq $s1, $s3, end_of_copy_blob_loop # if s1 == len(blob): break
        add $t0, $s0, $s1
        add $t2, $s2, $s1

        # *t2 = *t0
        lb $t4, 0($t0)
        sb $t4, 0($t2)

        add $s1, $s1, 1
        j copy_blob_loop
    end_of_copy_blob_loop:

    # Pad the copied blob: append \x80, then
    # as many \x00's until total length in bit
    # is a multiple of 448.
    li $t4, 0x80
    add $t2, $s2, $s1
    sb $t4, 0($t2)
    add $s1, $s1, 1
    pad_loop:
        sll $t1, $s1, 3
        and $t1, $t1, 0x1ff # mod 512
        li $t4, 448
        beq $t1, $t4, end_of_pad_loop # if len(padded_blob)<<3 == 448: break
        li $t4, 0x00
        add $t2, $s2, $s1
        sb $t4, 0($t2)
        add $s1, $s1, 1
        j pad_loop
    end_of_pad_loop:

    # Finish padding by storing the original message
    # length in bits as a big-endian quad word
    add $t2, $s2, $s1
    sw $zero, 0($t2)
    add $s1, $s1, 4

    lw $t1, 12($fp)
    sll $t1, $t1, 3
    add $t2, $s2, $s1
    sub $sp, $sp, 4
    sw $t2, 0($sp)
    sub $sp, $sp, 4
    sw $t1, 0($sp)
    jal sw_as_big_endian
    add $sp, $sp, 8
    add $s1, $s1, 4

    move $v0, $s2
    move $v1, $s1

    # Restore registers as expected by the caller
    lw $s3, -16($fp)
    lw $s2, -12($fp)
    lw $s1, -8($fp)
    lw $s0, -4($fp)
    add $sp, $sp, 16

    # cdecl epilogue
    move $sp, $fp
    lw $fp, 0($sp)
    add $sp, $sp, 4
    lw $ra, 0($sp)
    add $sp, $sp, 4
    jr $ra

left_rotate:
    ###
    # Left-rotate a 4 bytes word
    #
    # Args:
    #   n (int): word to left-rotate
    #   amount (int): amount of bits to shift by
    #
    # Returns:
    #   int: word left shifted by `amount` bits
    ###

    # cdecl prologue
    sub $sp, $sp, 4
    sw $ra, 0($sp)
    sub $sp, $sp, 4
    sw $fp, 0($sp)
    move $fp, $sp

    # Move s0, s1 to memory for later restore
    sub $sp, $sp, 8
    sw $s0, -4($fp)
    sw $s1, -8($fp)

    # s0, s1 = word, amount
    lw $s0, 8($fp)
    lw $s1, 12($fp)

    # t0 = word << amount
    move $t0, $s0
    sll $t0, $t0, $s1

    # t1 = word >> 32-amount
    li $t1, 32
    sub $t1, $t1, $s1
    srl $t1, $s0, $t1

    # return_value = t0 | t1
    or $v0, $t0, $t1

    # Restore registers as expected by the caller
    lw $s1, -8($fp)
    lw $s0, -4($fp)
    add $sp, $sp, 8

    # cdecl epilogue
    move $sp, $fp
    lw $fp, 0($sp)
    add $sp, $sp, 4
    lw $ra, 0($sp)
    add $sp, $sp, 4
    jr $ra

hexlify:
    ###
    # Produce the hexlified representation of a blob.
    #
    # Args:
    #   blob (char*)
    #   len (int): number of bytes to read starting from `blob`
    #
    # Returns:
    #   char*: address of the NULL terminated string with the hex
    #          representation of `blob`.
    ###

    # cdel prologue
    sub $sp, $sp, 4
    sw $ra, 0($sp)
    sub $sp, $sp, 4
    sw $fp, 0($sp)
    move $fp, $sp

    # Move s0, s1, s2 to memory for later restore
    sub $sp, $sp, 12
    sw $s0, -4($fp)
    sw $s1, -8($fp)
    sw $s2, -12($fp)

    # s0, s1 = blob, len
    lw $s0, 8($fp)
    lw $s1, 12($fp)

    # You need to store at least twice as bytes
    # as for each byte two hex digits are needed.
    mul $a0, $s1, 2
    add $a0, $a0, 1 # leave room for '\0'
    li $v0, 9
    syscall
    move $s2, $v0 # s2 = malloc(len*2 +1)

    li $t1, 0
    move $t0, $s0
    move $t2, $s2
    hexlify_loop:
        bge $t1, $s1, end_of_hexlify_loop

        # Leverage order of hexlify_map
        # such to use current byte's nibbles
        # as indeces.

        lbu $t3, 0($t0)
        srl $t3, $t3, 4
        la $t4, hexlify_map
        add $t4, $t4, $t3
        lbu $t3, 0($t4)
        sb $t3, 0($t2)
        add $t2, $t2, 1

        lbu $t3, 0($t0)
        and $t3, $t3, 0xf
        la $t4, hexlify_map
        add $t4, $t4, $t3
        lbu $t3, 0($t4)
        sb $t3, 0($t2)
        add $t2, $t2, 1

        add $t0, $t0, 1
        add $t1, $t1, 1
        j hexlify_loop
    end_of_hexlify_loop:

    li $t3, 0x00 # appending NULL character at the end
    sb $t3, 0($t2)
    move $v0, $s2

    # Restore registers as expected by the caller
    lw $s2, -12($fp)
    lw $s1, -8($fp)
    lw $s0, -4($fp)
    add $sp, $sp, 12

    # cdecl epilogue
    move $sp, $fp
    lw $fp, 0($sp)
    add $sp, $sp, 4
    lw $ra, 0($sp)
    add $sp, $sp, 4
    jr $ra


handle_chunk:
    ###
    # Use a chunk of 16 words to produce updated values for H0, H1,
    # H2, H3, H4 - the five registers used by SHA-1 to represent state.
    #
    # Args:
    #   chunk (char*)
    ###

    # cdecl prologue
    sub $sp, $sp, 4
    sw $ra, 0($sp)
    sub $sp, $sp, 4
    sw $fp, 0($sp)
    move $fp, $sp

    # Move s0, s1, s2, s3, s4, s5, s6, s7 to memory for later restore
    sub $sp, $sp, 32
    sw $s0, -4($fp)
    sw $s1, -8($fp)
    sw $s2, -12($fp)
    sw $s3, -16($fp)
    sw $s4, -20($fp)
    sw $s5, -24($fp)
    sw $s6, -28($fp)
    sw $s7, -32($fp)

    # s0, s1, s3 = chunk, 0, 64
    li $s1, 0
    li $s3, 64
    lw $s0, 8($fp)

    # A chunk needs 320bytes.
    li $a0, 320
    li $v0, 9
    syscall
    move $s2, $v0 # s2 = malloc(320)

    # Copy chunk of 64bytes to larger
    # allocated memory space of 320bytes.
    copy_chunk_loop:
        beq $s1, $s3, end_of_copy_chunk_loop
        add $t0, $s0, $s1
        add $t2, $s2, $s1
        lw $t4, 0($t0)
        sw $t4, 0($t2)
        add $s1, $s1, 4
        j copy_chunk_loop
    end_of_copy_chunk_loop:

    # Compute the remaining 64 4byte words as
    #
    #     w[i] = left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], amount=1)
    complete_manipulated_chunk_loop:
        li $s3, 320
        beq $s1, $s3, end_of_complete_manipulated_chunk_loop

        add $t4, $s2, $s1
        sub $t4, $t4, 12
        sub $sp, $sp, 4
        sw $t4, 0($sp)
        jal lw_as_big_endian
        add $sp, $sp, 4
        move $t4, $v0

        add $t5, $s2, $s1
        sub $t5, $t5, 32
        sub $sp, $sp, 4
        sw $t5, 0($sp)
        jal lw_as_big_endian
        add $sp, $sp, 4
        move $t5, $v0

        add $t6, $s2, $s1
        sub $t6, $t6, 56
        sub $sp, $sp, 4
        sw $t6, 0($sp)
        jal lw_as_big_endian
        add $sp, $sp, 4
        move $t6, $v0

        add $t7, $s2, $s1
        sub $t7, $t7, 64
        sub $sp, $sp, 4
        sw $t7, 0($sp)
        jal lw_as_big_endian
        add $sp, $sp, 4
        move $t7, $v0

        xor $t4, $t4, $t5
        xor $t4, $t4, $t6
        xor $t4, $t4, $t7

        sub $sp, $sp, 4
        li $t0, 1
        sw $t0, 0($sp)
        sub $sp, $sp, 4
        sw $t4, 0($sp)
        jal left_rotate
        add $sp, $sp, 8
        move $t4, $v0

        add $t2, $s2, $s1
        sub $sp, $sp, 4
        sw $t2, 0($sp)
        sub $sp, $sp, 4
        sw $t4, 0($sp)
        jal sw_as_big_endian
        add $sp, $sp, 8

        add $s1, $s1, 4
        j complete_manipulated_chunk_loop
    end_of_complete_manipulated_chunk_loop:

    # Changing registers semantics:
    # now s0 points to the manipulated chunk
    # while s2, s3, s4, s5, s6, s7 are
    # a, b, c, d, e, f. s1 is the i variable,
    # looping from 0 to 320.

    move $s0, $s2

    la $t0, state
    sub $sp, $sp, 4
    sw $t0, 0($sp)
    jal lw_as_big_endian
    move $s2, $v0
    add $sp, $sp, 4

    add $t0, $t0, 4
    sub $sp, $sp, 4
    sw $t0, 0($sp)
    jal lw_as_big_endian
    move $s3, $v0
    add $sp, $sp, 4

    add $t0, $t0, 4
    sub $sp, $sp, 4
    sw $t0, 0($sp)
    jal lw_as_big_endian
    move $s4, $v0
    add $sp, $sp, 4

    add $t0, $t0, 4
    sub $sp, $sp, 4
    sw $t0, 0($sp)
    jal lw_as_big_endian
    move $s5, $v0
    add $sp, $sp, 4

    add $t0, $t0, 4
    sub $sp, $sp, 4
    sw $t0, 0($sp)
    jal lw_as_big_endian
    move $s6, $v0
    add $sp, $sp, 4

    sub $t0, $t0, 20

    li $s1, 0 # int i=0;
    update_state_loop:
        li $t0, 80
        blt $s1, $t0, first_range
        li $t0, 160
        blt $s1, $t0, second_range
        li $t0, 240
        blt $s1, $t0, third_range
        li $t0, 320
        blt $s1, $t0, fourth_range
        j end_of_update_state_loop

        first_range:
            # f = (b & c) | (~b & d)
            and $t0, $s3, $s4
            not $t1, $s3
            and $t1, $t1, $s5
            or $s7, $t0, $t1

            li $t7, 0x5a827999
            j continue_of_update_state_loop

        second_range:
            # f = b ^ c ^ d
            xor $s7, $s3, $s4
            xor $s7, $s7, $s5

            li $t7, 0x6ed9eba1
            j continue_of_update_state_loop

        third_range:
            # f = (b & c) | (b & d) | (c & d)
            and $t0, $s3, $s4
            and $t1, $s3, $s5
            and $t2, $s4, $s5
            or $s7, $t0, $t1
            or $s7, $s7, $t2

            li $t7, 0x8f1bbcdc
            j continue_of_update_state_loop

        fourth_range:
            # f = b ^ c ^ d 
            xor $s7, $s3, $s4
            xor $s7, $s7, $s5

            li $t7, 0xca62c1d6
            j continue_of_update_state_loop

        continue_of_update_state_loop:
            # f = new_a = uint32_t(left_rotate(a, 5) + f + e + k + w[i])
            sub $sp, $sp, 4
            li $t0, 5
            sw $t0, 0($sp)
            sub $sp, $sp, 4
            sw $s2, 0($sp)
            jal left_rotate
            add $sp, $sp, 8
            addu $s7, $s7, $v0
            addu $s7, $s7, $s6
            addu $s7, $s7, $t7
            addu $t0, $s0, $s1
            sub $sp, $sp, 4
            sw $t0, 0($sp)
            jal lw_as_big_endian
            add $sp, $sp, 4
            move $t0, $v0
            addu $s7, $s7, $t0

            # e, d, c, b = d, c, left_rotate(b, 30), a
            move $s6, $s5
            move $s5, $s4
            sub $sp, $sp, 4
            li $t0, 30
            sw $t0, 0($sp)
            sub $sp, $sp, 4
            move $t0, $s3
            sw $t0, 0($sp)
            jal left_rotate
            add $sp, $sp, 8
            move $s4, $v0
            move $s3, $s2

            # a = new_a = f
            move $s2, $s7

            add $s1, $s1, 4
            j update_state_loop
    end_of_update_state_loop:

    # Now update state
    la $t0, state
    sub $sp, $sp, 4
    sw $t0, 0($sp)
    jal lw_as_big_endian
    add $sp, $sp, 4
    move $t4, $v0
    addu $t4, $t4, $s2
    sub $sp, $sp, 4
    sw $t0, 0($sp)
    sub $sp, $sp, 4
    sw $t4, 0($sp)
    jal sw_as_big_endian
    add $sp, $sp, 8

    la $t0, state
    add $t0, $t0, 4
    sub $sp, $sp, 4
    sw $t0, 0($sp)
    jal lw_as_big_endian
    add $sp, $sp, 4
    move $t4, $v0
    addu $t4, $t4, $s3
    sub $sp, $sp, 4
    sw $t0, 0($sp)
    sub $sp, $sp, 4
    sw $t4, 0($sp)
    jal sw_as_big_endian
    add $sp, $sp, 8

    la $t0, state
    add $t0, $t0, 8
    sub $sp, $sp, 4
    sw $t0, 0($sp)
    jal lw_as_big_endian
    add $sp, $sp, 4
    move $t4, $v0
    addu $t4, $t4, $s4
    sub $sp, $sp, 4
    sw $t0, 0($sp)
    sub $sp, $sp, 4
    sw $t4, 0($sp)
    jal sw_as_big_endian
    add $sp, $sp, 8

    la $t0, state
    add $t0, $t0, 12
    sub $sp, $sp, 4
    sw $t0, 0($sp)
    jal lw_as_big_endian
    add $sp, $sp, 4
    move $t4, $v0
    addu $t4, $t4, $s5
    sub $sp, $sp, 4
    sw $t0, 0($sp)
    sub $sp, $sp, 4
    sw $t4, 0($sp)
    jal sw_as_big_endian
    add $sp, $sp, 8

    la $t0, state
    add $t0, $t0, 16
    sub $sp, $sp, 4
    sw $t0, 0($sp)
    jal lw_as_big_endian
    add $sp, $sp, 4
    move $t4, $v0
    addu $t4, $t4, $s6
    sub $sp, $sp, 4
    sw $t0, 0($sp)
    sub $sp, $sp, 4
    sw $t4, 0($sp)
    jal sw_as_big_endian
    add $sp, $sp, 8

    # Restore registers as expected by the caller
    lw $s7, -32($fp)
    lw $s6, -28($fp)
    lw $s5, -24($fp)
    lw $s4, -20($fp)
    lw $s3, -16($fp)
    lw $s2, -12($fp)
    lw $s1, -8($fp)
    lw $s0, -4($fp)
    add $sp, $sp, 32

    # cdecl epilogue
    move $sp, $fp
    lw $fp, 0($sp)
    add $sp, $sp, 4
    lw $ra, 0($sp)
    add $sp, $sp, 4
    jr $ra

main: # Bootstrap function called by spim's __start()

    # cdecl epilogue
    sub $sp, $sp, 4
    sw $ra, 0($sp)
    sub $sp, $sp, 4
    sw $fp, 0($sp)
    move $fp, $sp

    # Move s0, s1 to memory for later restore
    sub $sp, $sp, 4
    sw $s0, 0($sp)
    sub $sp, $sp, 4
    sw $s1, 0($sp)

    # Allocate 1KB of room,
    li $a0, 0x400
    li $v0, 9
    syscall
    move $s0, $v0

    # ...read them from stdin
    li $a0, 0
    move $a1, $s0
    li $a2, 0x400
    li $v0, 14
    syscall
    move $s1, $v0

    # buffer = pad(buffer)
    sub $sp, $sp, 4
    sw $s1, 0($sp)
    sub $sp, $sp, 4
    sw $s0, 0($sp)
    jal pad
    add $sp, $sp, 8
    move $s0, $v0
    move $s1, $v1

    # Split blob in chunks of 64bytes,
    # handle each one while updating
    # SHA-1 states - H0, H1, H2, H3, H4
    handle_chunks_loop:
        sub $sp, $sp, 4
        sw $s0, 0($sp)
        jal handle_chunk
        add $sp, $sp, 4

        add $s0, $s0, 64
        sub $s1, $s1, 64
        bgtz $s1, handle_chunks_loop
    end_of_handle_chunks_loop:

    # puts(hexlify(state))
    sub $sp, $sp, 4
    li $t0, 20
    sw $t0, 0($sp)
    sub $sp, $sp, 4
    la $t0, state
    sw $t0, 0($sp)
    jal hexlify
    add $sp, $sp, 8
    move $a0, $v0
    li $v0, 4
    syscall
    li $a0, 0x0a
    li $v0, 11
    syscall

    # Restore registers as expected by the caller
    lw $s1, 0($sp)
    add $sp, $sp, 4
    lw $s0, 0($sp)
    add $sp, $sp, 4

    # cdecl epilogue
    move $sp, $fp
    lw $fp, 0($sp)
    add $sp, $sp, 4
    lw $ra, 0($sp)
    add $sp, $sp, 4
    jr $ra
