#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
"""Varint encoder/decoder
varints are a common encoding for variable length integer data, used in
libraries such as sqlite, protobuf, v8, and more.
Here's a quick and dirty module to help avoid reimplementing the same thing
over and over again.

https://github.com/fmoo/python-varint/blob/master/varint.py
"""

# byte-oriented StringIO was moved to io.BytesIO in py3k
try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO

import sys

if sys.version > "3":

    def _byte(b):
        return bytes((b,))


else:

    def _byte(b):
        return chr(b)


def encode(number: int) -> bytes:
    """Pack `number` into varint bytes"""
    buf = b""
    while True:
        towrite = number & 0x7F
        number >>= 7
        if number:
            buf += _byte(towrite | 0x80)
        else:
            buf += _byte(towrite)
            break
    return buf


def decode_stream(stream: BytesIO) -> int:
    """Read a varint from `stream`"""
    shift = 0
    result = 0
    while True:
        i = _read_one(stream)
        result |= (i & 0x7F) << shift
        shift += 7
        if not (i & 0x80):
            break

    return result


def decode_bytes(buf: bytes) -> int:
    """Read a varint from from `buf` bytes"""
    return decode_stream(BytesIO(buf))


def _read_one(stream: BytesIO):
    """Read a byte from the file (as an integer)
    raises EOFError if the stream ends while reading bytes.
    """
    c = stream.read(1)
    if c == b"":
        raise EOFError("Unexpected EOF while reading bytes")
    return ord(c)
