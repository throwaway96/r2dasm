#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Provides a wrapper around a file."""

from io import BufferedReader, SEEK_END, SEEK_SET

class FileBuffer:
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
