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


#-------------------------------------------------------------------
# Defines.
#-------------------------------------------------------------------
MAXVALUE_128_BITS = (2**128 - 1)
VERBOSE = False

#-------------------------------------------------------------------
# print_bytelist()
#-------------------------------------------------------------------
def print_bytelist(bl):
    print("[", end="")
    for i in range(len(bl)):
        print("0x%02x " % bl[i], end="")
    print("]")


#-------------------------------------------------------------------
# bl2hs()
#
#
#-------------------------------------------------------------------
def bl2hs(b):
    pass

#-------------------------------------------------------------------
# w2bl()
#
# Convert a given word into a list of bytes.
#-------------------------------------------------------------------
def w2bl(num_bytes, w):
    bl = []
    for i in range(num_bytes):
        b = w & 0xff
        bl.append(b)
        w = w >> 8
    return bl


#-------------------------------------------------------------------
# b2le()
#
# Convert a given list of bytes to a (huge) little endian word.
#-------------------------------------------------------------------
def b2le(blist):
    acc = 0
    for b in blist[::-1]:
        if VERBOSE:
            print("0x%02x" % (b), end=" ")
        acc = (acc << 8) + b
    if VERBOSE:
        print("")
    return acc


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
    p = (1<<130)-5
    print("Calculating new accumuator value")

    print("acc:         0x%033x" % acc)
    acc = (acc + b)
    print("acc + b:     0x%033x" % acc)
    acc = acc * r
    print("acc * r:     0x%065x" % acc)
    acc = acc % p
    print("acc mod p:   0x%033x" % acc)

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
        print("block word:       0x%033x" % b)
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
def verify_poly1305_tag(key, message, tag):
    return [0x01] * 16

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
#-------------------------------------------------------------------
def test_poly1305_update():
    print("*** Testing Poly1305 update.")
    acc = 0x00
    r = 0x806d5400e52447c036d555408bed685
    block = 0x6f4620636968706172676f7470797243
    acc = poly1305_update(acc, r, block)

    block = 0x6f7247206863726165736552206d7572
    acc = poly1305_update(acc, r, block)


#-------------------------------------------------------------------
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

    print("*** Testing Poly1305 mac.")

    my_tag = poly1305_mac(key, message)
    result = verify_poly1305_tag(key, message, my_tag)


#-------------------------------------------------------------------
# main()
#
# Run Poly1305 tests.
#-------------------------------------------------------------------
def main():
    print("Testing Poly1305")
    test_clamp_r()
    test_poly1305_mac()
#    test_poly1305_update()


#-------------------------------------------------------------------
#-------------------------------------------------------------------
if __name__=="__main__":
    sys.exit(main())

#=======================================================================
# EOF poly1305_test.py
#=======================================================================
