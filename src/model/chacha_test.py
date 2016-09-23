#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#=======================================================================
#
# chacha_test.py
# --------------
# Simple model of the ChaCha cipher as specified in RFC 7539
# (https://tools.ietf.org/html/rfc7539).
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


#-------------------------------------------------------------------
#-------------------------------------------------------------------
def print_chacha_state(state):
    print("chacha state:")
    print("0x%08x 0x%08x 0x%08x 0x%08x" % (state[00], state[1],  state[2],  state[3]))
    print("0x%08x 0x%08x 0x%08x 0x%08x" % (state[4],  state[5],  state[6],  state[7]))
    print("0x%08x 0x%08x 0x%08x 0x%08x" % (state[8],  state[9],  state[10], state[11]))
    print("0x%08x 0x%08x 0x%08x 0x%08x" % (state[12], state[13], state[14], state[15]))
    print("")


#-------------------------------------------------------------------
# rotl()
#
# Rotate 32-bit operand giveb number of bits left.
#-------------------------------------------------------------------
def rotl(op, bits):
    assert bits < 33
    return ((op << bits) + (op >> (32 - bits))) & 0xffffffff


#-------------------------------------------------------------------
# qr()
#
# The ChaCha quarterround function
#-------------------------------------------------------------------
def qr(a, b, c, d):
    a0 = (a + b) & 0xffffffff
    d0 = d ^ a0
    d1 = rotl(d0, 16)
    c0 = (c + d1) & 0xffffffff
    b0 = b ^ c0
    b1 = rotl(b0, 12)
    a1 = (a0 + b1) & 0xffffffff
    d2 = d1 ^ a1
    d3 = rotl(d2, 8)
    c1 = (c0 + d3) & 0xffffffff
    b2 = b1 ^ c1
    b3 = rotl(b2, 7)
    return (a1, b3, c1, d3)


#-------------------------------------------------------------------
# run_rotl_test()
#-------------------------------------------------------------------
def run_rotl_test():
    print("Test of rotl function.")
    for i in range(32):
        print("%02d: 0x%08x" % (i, rotl(0x10000001, i)))
    print("")


#-------------------------------------------------------------------
# run_qr_test()
#
# Test qr function with test vector in chapter 2.1.1.
#-------------------------------------------------------------------
def run_qr_test():
    a = 0x11111111
    b = 0x01020304
    c = 0x9b8d6f43
    d = 0x01234567
    (ap, bp, cp, dp) = qr(a, b, c, d)
    print("Test of qr function:")
    print("a:  0x%08x b:  0x%08x c:  0x%08x d:  0x%08x" % (a, b, c, d))
    print("ap: 0x%08x bp: 0x%08x cp: 0x%08x dp: 0x%08x" % (ap, bp, cp, dp))

    if ((ap != 0xea2a92f4) or (bp != 0xcb1cf8ce) or
        (cp != 0x4581472e) or (dp != 0x5881c4bb)):
        print("Incorrect result generated.")
    else:
        print("Correct result generated.")
    print("")


#-------------------------------------------------------------------
#-------------------------------------------------------------------
def run_qr_chacha_state_test():
    chacha_state = [0] * 16

    chacha_state[0]  = 0x879531e0
    chacha_state[1]  = 0xc5ecf37d
    chacha_state[2]  = 0x516461b1
    chacha_state[3]  = 0xc9a62f8a

    chacha_state[4]  = 0x44c20ef3
    chacha_state[5]  = 0x3390af7f
    chacha_state[6]  = 0xd9fc690b
    chacha_state[7]  = 0x2a5f714c

    chacha_state[8]  = 0x53372767
    chacha_state[9]  = 0xb00a5631
    chacha_state[10] = 0x974c541a
    chacha_state[11] = 0x359e9963

    chacha_state[12] = 0x5c971061
    chacha_state[13] = 0x3d631689
    chacha_state[14] = 0x2098d9d6
    chacha_state[15] = 0x91dbd320

    print_chacha_state(chacha_state)


#-------------------------------------------------------------------
#-------------------------------------------------------------------
def main():
    run_rotl_test()
    run_qr_test()
    run_qr_chacha_state_test()


#-------------------------------------------------------------------
#-------------------------------------------------------------------
if __name__=="__main__":
    sys.exit(main())

#=======================================================================
# EOF chacha_test.py
#=======================================================================
