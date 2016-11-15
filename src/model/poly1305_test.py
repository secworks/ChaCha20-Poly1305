#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#=======================================================================
#
# poly1305_test.py
# ----------------
# Simple model of the Poly1305 authenticator as specified in RFC 7539
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
from ch20p1305_utils import *

#-------------------------------------------------------------------
# Defines.
#-------------------------------------------------------------------
MAXVALUE_128_BITS = (2**128 - 1)
VERBOSE = False


#-------------------------------------------------------------------
# clamp_r()
#
# Perform the clamping of the Poly1305 r parameter.
#-------------------------------------------------------------------
def clamp_r(r):
    return r & 0x0ffffffc0ffffffc0ffffffc0fffffff


#-------------------------------------------------------------------
# poly1305_update()
#
# The inner core of the Poly1305 function. Given the state
# of the accumulator, the r parameter and a message block
# represented as a padded number it will calculate the
# updated value for the accumulator.
#-------------------------------------------------------------------
def poly1305_update(acc, r, b):
    p = 2**130 - 5
    print("")
    print("poly1305_update. Calculating new accumuator value with operands:")
    print("acc:       0x%033x" % acc)
    print("r:         0x%033x" % r)
    print("b:         0x%033x" % b)

    acc = (acc + b)
    print("acc + b:   0x%033x" % acc)
    acc = acc * r
    print("acc * r:   0x%065x" % acc)
    acc = acc % p
    print("acc mod p: 0x%033x" % acc)

    return acc


#-------------------------------------------------------------------
# poly1305_mac()
#
# The main Poly1305 function as specified in 2.5.1 in the RFC.
#-------------------------------------------------------------------
def poly1305_mac(key, message):
    # Extract r and s from key. Clamp r.
    r = b2le(key[0:16])
    s = b2le(key[16:32])
    cr = clamp_r(r)
    print("r:       0x%033x" % r)
    print("clamp_r: 0x%033x" % cr)
    print("s:       0x%033x" % s)

    # Calculate number of 16 byte chunks the message contains.
    blocks = int(len(message) / 16)
    lastbytes = len(message) - (16 * blocks)
    if (len(message) % 16):
        blocks += 1

    # Loop over the blocks, updating the accumulator.
    acc = 0
    for i in range(blocks):
        print("")
        block = message[i * 16 : i * 16 + 16]
        block.append(0x01)
        b = b2le(block)
        print("padded block %02d: " % i, end="")
        print_bytelist(block)
        print("block word:  0x%033x" % b)
        acc = poly1305_update(acc, cr, b)
    print("")

    # Generating the final tagword and convert to list of bytes.
    acc = acc + s
    print("acc + s:     0x%033x" % acc)
    tagword = acc & MAXVALUE_128_BITS
    print("tagword:     0x%033x" % tagword)
    tag = w2bl(16, tagword)
    print("tag:         ", end="")
    print_bytelist(tag)

    return tag


#-------------------------------------------------------------------
#-------------------------------------------------------------------
def test_clamp_r():
    rlist = [0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
             0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8]

    r = b2le(rlist)
    cr = clamp_r(r)

    print("*** Testing clamping of r.")
    print("r  = 0x%032x" % r)
    print("cr = 0x%032x" % cr)

    if (cr == 0x0806d5400e52447c036d555408bed685):
        print("Correct clamping of r.")
    else:
        print("Error: Incorrect clamping of r.")
    print("")


#-------------------------------------------------------------------
# test_poly1305_update()
#
# Test the poly1305_update function that calculates a new
# accumulator value based on give r, blockword and accumulator.
# The test vectors are from 2.5.2 in the RFC.
#-------------------------------------------------------------------
def test_poly1305_update():
    print("*** Testing Poly1305 update.")
    acc   = 0x00
    r     = 0x0806d5400e52447c036d555408bed685

    block1 = 0x6f4620636968706172676f7470797243
    acc1   = poly1305_update(acc, r, block1)

    block2 = 0x6f7247206863726165736552206d7572
    acc2   = poly1305_update(acc1, r, block2)

    block3 = 0x00000000000000000000000000007075
    acc3   = poly1305_update(acc1, r, block3)

    print("acc after block 1:  0x%033x" % acc1)
    print("acc after block 2:  0x%033x" % acc2)
    print("acc after block 3:  0x%033x" % acc3)

    if (acc1 != 0x2c88c77849d64ae9147ddeb88e69c83fc):
        print("Expected acc1: 0x2c88c77849d64ae9147ddeb88e69c83fc")
    if (acc2 != 0x2d8adaf23b0337fa7cccfb4ea344b30de):
        print("Expected acc2: 0x2d8adaf23b0337fa7cccfb4ea344b30de")
    if (acc3 != 0x28d31b7caff946c77c8844335369d03a7):
        print("Expected acc2: 0x28d31b7caff946c77c8844335369d03a7")


#-------------------------------------------------------------------
# test_poly1305_mac()
#
# Test program for the Poly1305_mac function. Test vectors
# are from 2.5.2 in the RFC.
#-------------------------------------------------------------------
def test_poly1305_mac():
    key = [0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
           0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
           0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
           0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b]

    message = [0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72,
               0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x6f,
               0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65,
               0x61, 0x72, 0x63, 0x68, 0x20, 0x47, 0x72, 0x6f,
               0x75, 0x70]

    expected = [0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
                0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9]

    print("*** Testing Poly1305 mac.")

    my_tag = poly1305_mac(key, message)
    print("")
    if my_tag == expected:
        print("Correct tag generated.")
    else:
        print("Incorrect tag generated.")
    print("")


#-------------------------------------------------------------------
# main()
#
# Run Poly1305 tests.
#-------------------------------------------------------------------
def main():
    print("Testing Poly1305")
    test_clamp_r()
    # test_poly1305_update()
    test_poly1305_mac()


#-------------------------------------------------------------------
#-------------------------------------------------------------------
if __name__=="__main__":
    sys.exit(main())

#=======================================================================
# EOF poly1305_test.py
#=======================================================================
