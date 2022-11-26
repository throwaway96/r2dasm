#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""MStar Aeon R2 disassembler."""

from struct import unpack
from typing import Final

from filebuffer import FileBuffer
from insn import R2Insn, INSN_LENGTH_IDX, INSNS


TEST_INPUTS: Final[list[str]] = [
    'tzfw_100180_c0.bin', 'tzfw_100280_e0.bin', 'fpf.bin',
    'MAsm_CPU_DelayUs.bin',
    #'ret.bin',
    #'MAsm_CPU_Nop.bin',
    #'MAsm_CPU_Sync.bin',
    #'MAsm_CPU_SwDbgBp.bin',
    #'MAsm_CPU_TimerInit.bin',
    ]

ZEROES: Final[bytes] = b'\x00' * 4

def dasm_at(fbuf: FileBuffer, offset: int) -> R2Insn:
    """Disassemble single instruction at offset."""
    assert offset >= 0

    # insn can be up to 4 bytes long
    data: bytes = fbuf.read(offset, 4)

    ms_byte: int
    (ms_byte,) = unpack('B', data[0:1])

    # top three bits determine length
    length_index: int = ms_byte >> 5

    length: int = INSN_LENGTH_IDX[length_index]

    assert 0 < length <= 4

    raw: bytes = data[0:length]

    bits: int
    (bits,) = unpack('>I', ZEROES[0:4 - length] + raw)

    for templ in INSNS:
        if templ.length != length:
            continue

        if templ.match(bits):
            insn: R2Insn = templ.parse(bits)
            insn.raw = raw
            return insn

    # unknown instruction
    insn = R2Insn(length, bits)
    insn.raw = raw
    return insn


def dasm(fbuf: FileBuffer) -> None:
    """Disassemble entire buffer."""
    offset: int = 0

    length: int = len(fbuf)

    while offset < length:
        insn: R2Insn = dasm_at(fbuf, offset)

        print(f"{offset:08x}: {insn.raw.hex(' '):18s} {insn}")

        offset += insn.length


def main() -> None:
    """Entry point."""
    filename: str

    for filename in TEST_INPUTS:
        print(f"*** {filename} ***")

        with open(filename, 'rb') as fp:
            fbuf: FileBuffer = FileBuffer(fp)
            dasm(fbuf)

        print("\n")


if __name__ == '__main__':
    main()
