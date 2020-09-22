#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2020 Andy Wang <ci_knight@msn.cn>
#
# Distributed under terms of the MIT license.
from hashlib import blake2b
from consts import Blake2bConfig, payloadHashConfig


# Bytes to Str
def b2s(b: bytes) -> str:
    return b.decode("latin-1")


# Str to Bytes
def s2b(s: str) -> bytes:
    return s.encode("latin-1")


def _hash(b: bytes, config: Blake2bConfig) -> bytes:
    hexdigest = blake2b(b, digest_size=config.size).hexdigest()
    return s2b(hexdigest)


def address_hash(b: bytes) -> bytes:
    return _hash(b, payloadHashConfig)
