#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2020 Andy Wang <ci_knight@msn.cn>
#
# Distributed under terms of the MIT license.
from base64 import b32encode
from typing import Union
from hashlib import blake2b
from consts import Blake2bConfig, payloadHashConfig, checksumHashConfig


# Bytes to Str
def b2s(b: bytes) -> str:
    return b.decode("latin-1")


# Str to Bytes
def s2b(s: Union[str, int]) -> bytes:
    s = str(s)
    return s.encode("latin-1")


def _hash(ingest: bytes, config: Blake2bConfig) -> bytes:
    hexdigest = blake2b(ingest, digest_size=config.size).hexdigest()
    return s2b(hexdigest)


def address_hash(ingest: bytes) -> bytes:
    return _hash(ingest, payloadHashConfig)


# Checksum returns the checksum of `ingest`.
def checksum(ingest: bytes):
    return _hash(ingest, checksumHashConfig)


# ValidateChecksum returns true if the checksum of `ingest` is equal to `expected`>
def validate_checksum(ingest: bytes, expect: bytes) -> bool:
    return checksum(ingest) == expect


def address_encode(ingest: bytes) -> str:
    return b32encode(ingest).decode()
