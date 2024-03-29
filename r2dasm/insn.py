#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Final


INSN_LENGTH_IDX: Final[list[int]] = [
    3, # 0b000 (0) -> 3 bytes
    3, # 0b001 (1) -> 3 bytes
    3, # 0b010 (2) -> 3 bytes
    3, # 0b011 (3) -> 3 bytes
    2, # 0b100 (4) -> 2 bytes
    4, # 0b101 (5) -> 4 bytes
    4, # 0b110 (6) -> 4 bytes
    4, # 0b111 (7) -> 4 bytes
]

# 'x', 'y' are made-up placeholders
VALID_ARGS: Final[set[str]] = {'a', 'b', 'd', 'i', 'j', 'k', 'n', 'x', 'y'}

class BitRange:
    """A range of bits."""

    length: int
    """Number of bits in this range."""
    insn_offset: int
    """Offset of range within instruction, from the instruction LSB to range LSB."""
    value_offset: int
    """Offset of range within output value."""

    def __init__(self, length: int, insn_offset: int, value_offset: int):
        self.length = length
        self.insn_offset = insn_offset
        self.value_offset = value_offset

    def extract_part(self, instruction: int) -> int:
        """Get the value of this bit range."""
        value: int = ((instruction >> self.insn_offset) & ((1 << self.length) - 1))

        return value << self.value_offset


class R2OperandTempl:
    arg: str
    mask: int
    signed: bool = False
    bit_length: int
    ranges: list[BitRange]

    def __init__(self, arg: str, template: str, *, signed: bool = False):
        assert arg in VALID_ARGS
        self.arg = arg

        template_lower: str = template.lower()

        assert arg in template_lower

        self.template = ''.join(arg if ch == arg else '-' for ch in template_lower)

        template_len: int = len(self.template)

        self.mask = int(''.join('1' if ch == arg else '0' for ch in self.template), 2)

        self.bit_length = template.count(arg)

        self.signed = signed

        self.ranges = []

        value_offset: int = 0
        search_index: int = template_len

        while search_index != -1:
            assert search_index >= 0

            lsb_index: int = self.template.rfind(arg, 0, search_index)

            if lsb_index == -1:
                # no more bits
                break

            # this works even if -1 is returned, because then the MSB is at index 0
            msb_index: int = self.template.rfind('-', 0, lsb_index) + 1

            run_length: int = lsb_index - msb_index + 1
            lsb_offset: int = template_len - lsb_index - 1

            self.ranges.append(BitRange(run_length, lsb_offset, value_offset))

            value_offset += run_length
            search_index = msb_index - 1


    def extract(self, instruction: int) -> 'R2Operand':
        """Decode the value of this operand from instruction."""
        assert self.bit_length > 0

        value: int = 0

        for bit_range in self.ranges:
            value |= bit_range.extract_part(instruction)

        if self.signed:
            # check if value is negative
            sign_bit: int = 1 << (self.bit_length - 1)

            if (value & sign_bit) != 0:
                # invert value
                mask: int = (1 << self.bit_length) - 1

                value ^= mask
                value += 1
                value = -value

        return R2Operand(self, value)


class R2Operand:
    arg: str
    signed: bool
    bit_length: int
    value: int
    template: R2OperandTempl

    def __init__(self, template: R2OperandTempl, value: int):
        self.template = template
        self.arg = template.arg
        self.bit_length = template.bit_length
        self.signed = template.signed

        self.value = value

class R2InsnTempl:
    mnemonic: str
    length: int
    length_bits: int
    bits: int
    mask: int
    bits_template: str
    args: set[str]
    opr_templates: dict[str, R2OperandTempl]
    args_format: str
    signed_args: set[str]

    def __init__(self, mnemonic: str, length: int, bits_template: str, args_format: str | None = None, *,
                 signed: set[str] | None = None):
        assert mnemonic != ''
        self.mnemonic = mnemonic

        assert length > 0
        self.length = length
        self.length_bits = length * 8

        assert bits_template != ''
        self.bits_template = bits_template.lower()

        # ensure bits_template is the correct length
        assert self.length_bits == len(bits_template)

        if args_format is None:
            # default to no args
            self.args_format = ''
        else:
            assert args_format != ''
            self.args_format = args_format

        self.args = set(self.bits_template)

        self.args.discard('0')
        self.args.discard('1')

        # check that the args are all in VALID_ARGS
        assert self.args <= VALID_ARGS

        if signed is not None:
            assert signed <= self.args
            self.signed_args = signed
        else:
            self.signed_args = set()


        self.opr_templates = {}

        arg: str
        for arg in self.args:
            self.opr_templates[arg] = R2OperandTempl(arg, self.bits_template, signed=arg in self.signed_args)

        self.bits = int(''.join(ch if ch in {'0', '1'} else '0' for ch in self.bits_template), 2)
        self.mask = int(''.join('1' if ch in {'0', '1'} else '0' for ch in self.bits_template), 2)

    def match(self, instruction: int) -> bool:
        """Check whether an instruction matches this template."""
        return (instruction & self.mask) == self.bits

    def parse(self, instruction: int) -> 'R2Insn':
        """Decode an instruction using this template."""
        args: dict[str, R2Operand] = {}

        for (arg, templ) in self.opr_templates.items():
            args[arg] = templ.extract(instruction)

        return R2Insn(self.length, instruction, self, args)

INSNS: list[R2InsnTempl] = [
    # 16-bit / 2-byte / "BT"?
    R2InsnTempl('l.nop',    2, '1000000000000001'),                               # disasm; guess
    # XXX: don't know how to decode
    R2InsnTempl('bt.trap',  2, '1000000000000010', '1'),                          # disasm
    R2InsnTempl('l.jr?',    2, '100001xxxxxyyyyy', '??? r%x, r%y'),               # disasm
    # XXX: not sure 
    R2InsnTempl('l.add?',   2, '100011dddddaaaaa', 'r%d, r%d, r%a'),              # guess
    R2InsnTempl('l.j',      2, '100100nnnnnnnnnn', '%n'),                         # chenxing
    # XXX: may be a mov-type insn that sets rD <- K
    R2InsnTempl('l.andi?',  2, '100110dddddkkkkk', 'r%d, r%d, %k', signed={'k'}), # disasm, guess
    R2InsnTempl('l.addi',   2, '100111dddddkkkkk', 'r%d, r%d, %k', signed={'k'}), # backtrace, guess

    # 24-bit / 3-byte / "BN"?
    R2InsnTempl('l.nop',   3, '000000000000000000000000'),                    # chenxing
    # XXX: top bits of k may be a register, and this is an or?
    R2InsnTempl('l.movhi?',3, '000001dddddkkkkkkkkkkkkk', 'r%d, %k'),
    R2InsnTempl('l.lhz',   3, '000010dddddaaaaa00000001', 'r%d, 0(r%a)'),     # chenxing
    R2InsnTempl('l.sw',    3, '000011bbbbbaaaaaiiiiii00', '%i(r%a), r%b', signed={'i'}),# chenxing, backtrace
    # XXX: assuming this is l.lwz and not l.lws
    R2InsnTempl('l.lwz?',  3, '000011dddddaaaaaiiiiii10', 'r%d, %i(r%a)', signed={'i'}),# guess
    # XXX: assuming this is l.lwz and not l.lws
    R2InsnTempl('l.lwz?',  3, '000100dddddaaaaaiiiiii00', 'r%d, %i(r%a)', signed={'i'}),# guess
    R2InsnTempl('l.sw?',   3, '000110bbbbbaaaaaiiiiii00', '%i(r%a), r%b', signed={'i'}),#guess
    R2InsnTempl('l.addi',  3, '000111dddddaaaaakkkkkkkk', 'r%d, r%a, %k', signed={'k'}),# chenxing, backtrace
    R2InsnTempl('l.bf',    3, '001000nnnnnnnnnnnnnnnn01', '%n', signed={'n'}),# chenxing(mod), disasm
                             # 001000000110000000101100
    R2InsnTempl('?cmpjmp?',3, '001001aaaaaiiinnnnnnnn01', 'r%a, %i, %n', signed={'n'}),# wild guess
    R2InsnTempl('l.movhi', 3, '001101100000000000000001', 'r1, ???'),         # chenxing
    R2InsnTempl('l.mul',   3, '010000dddddaaaaabbbbb011', 'r%d, r%a, r%b'),   # disasm
    R2InsnTempl('l.and',   3, '010001dddddaaaaabbbbb100', 'r%d, r%a, r%b'),   # chenxing
    R2InsnTempl('l.or?',   3, '010001dddddaaaaabbbbb101', 'r%d, r%a, r%b'),   # guess
    R2InsnTempl('l.ori',   3, '010100dddddaaaaakkkkkkkk', 'r%d, r%a, %k'),    # chenxing
    R2InsnTempl('l.andi',  3, '010101dddddaaaaakkkkkkkk', 'r%d, r%a, %k'),    # guess
    R2InsnTempl('l.sfgtui',3, '010111aaaaaiiiiiiii11011', 'r%a, %i', signed={'i'}), # disasm
    R2InsnTempl('?entri?', 3, '010111xxxxyyyyyyyyy11000', '??? %x, %y'),      # backtrace
    R2InsnTempl('l.sfeqi', 3, '010111aaaaaiiiii00000001', 'r%a, %i'),         # chenxing
    R2InsnTempl('l.sfne',  3, '010111aaaaabbbbb00001101', 'r%a, r%b'),        # chenxing
    R2InsnTempl('l.sfgeu', 3, '010111bbbbbaaaaa00010111', 'r%a, r%b'),        # chenxing

    # 32-bit / 4-byte / "BG"?
    R2InsnTempl('l.movhi', 4, '110000dddddkkkkkkkkkkkkkkkk00001', 'r%d, %k'),                # chenxing(mod), disasm
    R2InsnTempl('l.mtspr', 4, '110000bbbbbaaaaakkkkkkkkkkkk1101', 'r%a, r%b, %k'),           # chenxing
    R2InsnTempl('l.mfspr', 4, '110000dddddaaaaakkkkkkkkkkkk1111', 'r%d, r%a, %k'),           # chenxing
    R2InsnTempl('l.andi',  4, '110001dddddaaaaakkkkkkkkkkkkkkkk', 'r%d, r%a, %k'),           # chenxing
    R2InsnTempl('l.ori',   4, '110010dddddaaaaakkkkkkkkkkkkkkkk', 'r%d, r%a, %k'),           # chenxing
    # XXX: n is probably wrong
    R2InsnTempl('l.bf',    4, '11010100nnnnnnnnnnnnnnnnnnnnnnnn', '%n', signed={'n'}),       # disasm, guess
    # XXX: n is probably wrong
    R2InsnTempl('l.jal?',  4, '111001nnnnnnnnnnnnnnnnnnnnnnnnnn', '%n', signed={'n'}),       # guess
    R2InsnTempl('l.j',     4, '111010nnnnnnnnnnnnnnnnnnnnnnnn11', '%n', signed={'n'}),       # chenxing
    R2InsnTempl('l.sw',    4, '111011bbbbbaaaaaiiiiiiiiiiiiii00', '%i(r%a), r%b', signed={'i'}), # chenxing, backtrace
    R2InsnTempl('l.lwz?',  4, '111011dddddaaaaaiiiiiiiiiiiiii10', 'r%d, %i(r%a)', signed={'i'}), # guess
    R2InsnTempl('l.addi',  4, '111111dddddaaaaakkkkkkkkkkkkkkkk', 'r%d, r%a, %k'),           # chenxing, backtrace
    
    R2InsnTempl('l.invalidate_line', 4, '11110100000aaaaa00000000000j0001', '0(r%a), %j'),   # chenxing
    R2InsnTempl('l.invalidate_line', 4, '11110100000aaaaa00000000001j0111', '0(r%a), %j'),   # disasm
    R2InsnTempl('l.syncwritebuffer', 4, '11110100000000000000000000000101'),                 # disasm
]


class R2Insn:
    """A disassembled instruction."""
    length: int
    bits: int
    template: R2InsnTempl | None
    args: dict[str, R2Operand] | None
    raw: bytes

    def __init__(self, length: int, bits: int, template: R2InsnTempl | None = None, args: dict[str, R2Operand] | None = None):
        self.template = template
        self.length = length
        self.bits = bits
        self.args = args

    def arg_subst(self, match: re.Match[str]) -> str:
        arg: str = match.group(2)

        # for escaping %
        if arg == '%':
            return '%'

        assert arg in VALID_ARGS
        assert self.args is not None
        assert arg in self.args

        value: int = self.args[arg].value

        # XXX: hack
        if match.group(1) == 'r':
            # register
            assert value >= 0

            return f"r{value:d}"
        else:
            return f"{value:#x}"

    def __str__(self) -> str:
        if self.template is None:
            return '*unk*'

        args: str = re.sub(r'(r?)%(.)', self.arg_subst, self.template.args_format)

        return f"{self.template.mnemonic:12s} {args}"
