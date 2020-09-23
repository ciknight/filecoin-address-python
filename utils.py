#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2020 Andy Wang <ci_knight@msn.cn>
#
# Distributed under terms of the MIT license.
import binascii
import struct
from base64 import b32encode
from typing import Union
from hashlib import blake2b
from consts import Blake2bConfig, payloadHashConfig, checksumHashConfig


# Bytes to Str
def b2s(b: bytes) -> str:
    if len(b) == 1:
        return str(struct.unpack("b", b)[0])

    return binascii.hexlify(b).decode()


# Str to Bytes
def s2b(s: Union[str, int]) -> bytes:
    if isinstance(s, int):
        return struct.pack("b", s)

    return binascii.unhexlify(s)


def _hash(ingest: bytes, config: Blake2bConfig) -> bytes:
    return blake2b(ingest, digest_size=config.size).digest()


def address_hash(ingest: bytes) -> bytes:
    return _hash(ingest, payloadHashConfig)


# Checksum returns the checksum of `ingest`.
def checksum(ingest: bytes) -> bytes:
    return _hash(ingest, checksumHashConfig)


# ValidateChecksum returns true if the checksum of `ingest` is equal to `expected`>
def validate_checksum(ingest: bytes, expect: bytes) -> bool:
    return checksum(ingest) == expect


def address_encode(ingest: bytes) -> str:
    return b32encode(ingest).decode().lower().rstrip("=")
