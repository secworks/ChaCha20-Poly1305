#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#=======================================================================
#
# ch20p1305.py
# ------------
# Simple model of the Chacha20-Poly1305 construction as specified
# in RFC 7539 (https://tools.ietf.org/html/rfc7539). The model
# uses the test vectors in the RFC.
#
# The model is used as a reference for the HW implementation.
# The code follows the structure of the HW implementation as much
# as possible.
#
#
# Copyright (c) 2016 Secworks Sweden AB
# Author: Joachim Strömbergson
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#=======================================================================

#-------------------------------------------------------------------
# Python module imports.
#-------------------------------------------------------------------
import sys
from chacha_test import chacha_encryption
from chacha_test import chacha_block
from chacha_test import l2lw32
from chacha_test import w32bl
from poly1305_test import print_bytelist


#-------------------------------------------------------------------
# Constants.
#-------------------------------------------------------------------


#-------------------------------------------------------------------
# poly1305_keygen_test()
#
# Test that we can generate a correct Poly1305 key using chacha20.
# Testvectors from 2.6.2 in the RFC.
#-------------------------------------------------------------------
def poly1305_keygen_test():
    key_bytes = [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f]
    key = l2lw32(key_bytes)

    nonce_bytes = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
                   0x04, 0x05, 0x06, 0x07]
    nonce = l2lw32(nonce_bytes)

    counter = 0x00000000;

    print("*** Test of the Poly1305 key generation using ChaCha20 block function.")

    block = chacha_block(key, counter, nonce)
    print("Generated block bytes:")
    block_bytes = w32bl(block)
    print_bytelist(block_bytes)
    print()
    p1305_key_bytes = block_bytes[0:32]
    print("Generated key bytes:")
    print_bytelist(p1305_key_bytes)
    print()


#-------------------------------------------------------------------
# ch20p1305_tests()
#-------------------------------------------------------------------
def ch20p1305_tests():
    key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

    counter = 0x00000001

    nonce = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
             0x00, 0x00, 0x00, 0x00]

    ptext = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

    print("*** Test of the Ch20P1305 AEAD function.")
    ciphertext = chacha_encryption(key, counter, nonce, ptext)
    print("Ciphertext:")
    print(ciphertext)
    print()

#-------------------------------------------------------------------
# main()
#
# If executed tests the ChaCha class using known test vectors.
#-------------------------------------------------------------------
def main():
    ch20p1305_tests()
    poly1305_keygen_test()

#-------------------------------------------------------------------
# __name__
# Python thingy which allows the file to be run standalone as
# well as parsed from within a Python interpreter.
#-------------------------------------------------------------------
if __name__=="__main__":
    # Run the main function.
    sys.exit(main())

#=======================================================================
# EOF chacha.py
#=======================================================================
