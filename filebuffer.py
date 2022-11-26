#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Provides a Python list-like wrapper around a file."""

from io import BufferedReader, SEEK_END, SEEK_SET
from collections.abc import ByteString
from typing import overload

class FileBuffer(ByteString):
    """Basically a file."""
    file: BufferedReader
    _len: int | None = None

    def __init__(self, file: BufferedReader) -> None:
        self.file = file

    def __len__(self) -> int:
        """Get length of buffer."""
        if self._len is None:
            # save current position
            orig_pos: int = self.file.tell()

            # go to end of buffer and get offset
            self._len = self.file.seek(0, SEEK_END)

            # return to original position
            self.file.seek(orig_pos, SEEK_SET)

        return self._len


    def read(self, offset: int, size: int) -> bytes:
        """Read given number of bytes from buffer at offset."""
        if offset >= 0:
            self.file.seek(offset, SEEK_SET)
        else:
            # negative offsets are relative to end of file
            self.file.seek(offset, SEEK_END)

        return self.file.read(size)

    @overload
    def __getitem__(self, key: int) -> int: ...
    @overload
    def __getitem__(self, key: slice) -> bytes: ...
    def __getitem__(self, key: int | slice) -> bytes | int:
        if isinstance(key, int):
            if abs(key) >= len(self):
                raise IndexError('Tried to read past end of file')

            return self.read(key, 1)[0]
        elif isinstance(key, slice):
            if key.step is not None:
                raise TypeError('Slices with step not supported')

            if abs(key.start) >= len(self) or abs(key.stop) > len(self):
                raise IndexError('Tried to read past end of file')

            start: int
            if key.start is None:
                start = 0
            else:
                start = key.start if key.start >= 0 else len(self) - key.start

            stop: int
            if key.stop is None:
                stop = 0
            else:
                stop = key.stop if key.stop >= 0 else len(self) - key.stop

            return self.read(start, stop - start)
        else:
            raise TypeError('Index must be int or slice')
