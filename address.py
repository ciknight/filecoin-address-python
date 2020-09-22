#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2020 Andy Wang <ci_knight@msn.cn>
#
# Distributed under terms of the MIT license.
import varints
from exceptions import AddressException
from consts import PayloadHashLength, BlsPublicKeyBytes
from utils import b2s


class NetWork:
    Mainnet = 0
    Testnet = 1


class Prefix:
    Mainnet = "f"
    Testnet = "t"


class Protocol:
    ID = 0
    SECP256K1 = 1
    Actor = 2
    BLS = 3


class Address:
    def __init__(self, payload: str = None):
        self.payload = payload

    def __repr__(self):
        return f"Address({repr(self.payload)})"


def new_address(protocol: int, payload: bytes) -> Address:
    if protocol == Protocol.ID:
        # TODO verify payload
        _ = varints.decode_bytes(payload)
    elif protocol in (Protocol.SECP256K1, Protocol.Actor):
        if len(payload) != PayloadHashLength:
            raise AddressException()
    elif protocol == Protocol.BLS:
        if len(payload) != BlsPublicKeyBytes:
            raise AddressException()
    else:
        raise NotImplementedError

    buf = str(protocol) + b2s(payload)
    return Address(buf)


# NewIDAddress returns an address using the ID protocol.
def new_id_address(id_: int) -> Address:
    if id_ > 2 ** 63:
        raise AddressException("IDs must be less than 2^63")

    return new_address(Protocol.ID, varints.encode(id_))
