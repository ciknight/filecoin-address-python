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
from utils import s2b, address_hash, checksum, address_encode


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

    Unknown = 255


class Address:
    def __init__(self, payload: bytes):
        self._payload = payload

    @property
    def protocol(self) -> int:
        if len(self.payload) == 0:
            return Protocol.Unknown

        return int(self._payload[0])

    @property
    def payload(self) -> bytes:
        return self._payload[1:]

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

    buf = s2b(protocol) + payload
    return Address(buf)


# NewIDAddress returns an address using the ID protocol.
def new_id_address(id_: int) -> Address:
    if id_ > 2 ** 63:
        raise AddressException("IDs must be less than 2^63")

    return new_address(Protocol.ID, varints.encode(id_))


# NewSecp256k1Address returns an address using the SECP256K1 protocol.
def new_spec256k1_address(pubkey: bytes) -> Address:
    return new_address(Protocol.SECP256K1, address_hash(pubkey))


def encode(network: int, addr: Address):
    if network == NetWork.Mainnet:
        ntwk = Prefix.Mainnet
    elif network == NetWork.Testnet:
        ntwk = Prefix.Testnet
    else:
        raise AddressException(f"Error network {network}")

    addr_str: str = ""
    if addr.protocol in (Protocol.SECP256K1, Protocol.Actor, Protocol.BLS):
        cksm = checksum(s2b(addr.protocol) + addr.payload)
        addr_str = f"{ntwk}{addr.protocol}{address_encode(addr.payload + cksm)}"
    elif addr.protocol == Protocol.ID:
        raise NotImplementedError
    else:
        raise AddressException(f"Error protocol {addr.protocol}")

    return addr_str
