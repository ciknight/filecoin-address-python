#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2020 Andy Wang <ci_knight@msn.cn>
#
# Distributed under terms of the MIT license.
from typing import Union

from address import varints
from address.consts import (
    BlsPublicKeyBytes,
    MaxAddressStringLength,
    MinAddressStringLength,
    PayloadHashLength,
)
from address.exceptions import AddressException
from address.utils import (
    address_decode,
    address_encode,
    address_hash,
    b2s,
    checksum,
    s2b,
    validate_checksum,
)


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

    All = {
        ID,
        SECP256K1,
        Actor,
        BLS,
    }


class Address:
    def __init__(self, payload: bytes):
        self._payload = payload

    @property
    def protocol(self) -> int:
        if len(self._payload) == 0:
            return Protocol.Unknown

        return int(b2s(self._payload[:1]))

    @property
    def payload(self) -> bytes:
        return self._payload[1:]

    def checksum(self) -> bytes:
        return checksum(s2b(self.protocol) + self.payload)

    def to_string(self) -> str:
        return encode(NetWork.Testnet, self)

    def __repr__(self):
        return f"Address({repr(self.to_string())})"


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
def new_spec256k1_address(pubkey: Union[bytes, str]) -> Address:
    if isinstance(pubkey, str):
        pubkey = s2b(pubkey)

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
        addr_str = (
            f"{ntwk}{addr.protocol}{address_encode(addr.payload + addr.checksum())}"
        )
    elif addr.protocol == Protocol.ID:
        raise NotImplementedError
    else:
        raise AddressException(f"Error protocol {addr.protocol}")

    return addr_str


def decode(a: str) -> Address:
    if len(a) == 0:
        raise AddressException("Address string is null")

    if len(a) > MaxAddressStringLength or len(a) < MinAddressStringLength:
        raise AddressException("Invalid address length")

    if a[0] != Prefix.Mainnet and a[0] != Prefix.Testnet:
        raise AddressException("Invalid address network")

    protocol = int(a[1])
    if protocol not in Protocol.All:
        raise AddressException("Invalid address protocol")

    raw = a[2:]
    if protocol == Protocol.ID:
        # 20 is length of math.MaxUint64 as a string
        if len(raw) > 20:
            raise AddressException("Invalid address length")

        return new_address(protocol, varints.encode(int(raw)))

    payloadcksm = address_decode(raw)
    payload, cksm = payloadcksm[:-4], payloadcksm[-4:]

    if validate_checksum(s2b(protocol) + payload, cksm) is False:
        raise AddressException("Invalid payload")

    return new_address(protocol, payload)
