#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2020 Andy Wang <ci_knight@msn.cn>
#
# Distributed under terms of the MIT license.
class Blake2bConfig:
    def __init__(self, size: int):
        self.size = size


# PayloadHashLength defines the hash length taken over addresses using the Actor and SECP256K1 protocols.
PayloadHashLength = 20

# ChecksumHashLength defines the hash length used for calculating address checksums.
ChecksumHashLength = 4

# MaxAddressStringLength is the max length of an address encoded as a string
# it include the network prefx, protocol, and bls publickey
MaxAddressStringLength = 2 + 84

# BlsPublicKeyBytes is the length of a BLS public key
BlsPublicKeyBytes = 48

# BlsPrivateKeyBytes is the length of a BLS private key
BlsPrivateKeyBytes = 32


payloadHashConfig = Blake2bConfig(PayloadHashLength)
checksumHashConfig = Blake2bConfig(ChecksumHashLength)

encodeStd = "abcdefghijklmnopqrstuvwxyz234567"
