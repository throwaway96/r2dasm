# r2dasm

This is an quick first attempt at a disassembler for MStar AEON R2, written while I was reversing the instruction set. It is highly incomplete and has many inaccuracies, as it was only intended as a research aid and not for public use.

The work continued in the form of additions to [reko](https://github.com/uxmal/reko/), and the R2 instruction set is now effectively completely reverse engineered. However, there may still be specialzed (e.g., vector/SIMD) instructions that we haven't seen examples of yet. The reko work was used by [shinyquagsire23](https://github.com/shinyquagsire23) as the basis of [ghidra-aeon](https://github.com/shinyquagsire23/ghidra-aeon).
