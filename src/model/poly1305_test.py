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
# b2le()
#
# Convert a given list of bytes to a (huge) little endian word.
#-------------------------------------------------------------------
def b2le(blist):
    acc = 0
    for b in blist[::-1]:
        print("0x%02x" % (b), end=" ")
        acc = (acc << 8) + b
    print("")
    return acc


#-------------------------------------------------------------------
#-------------------------------------------------------------------
def clamp_r(r):
    return r & 0x0ffffffc0ffffffc0ffffffc0fffffff


#-------------------------------------------------------------------
#-------------------------------------------------------------------
def gen_poly1305_tag(key, message):
    return [0x01] * 16

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

    print("*** Testing clamping of r.")
    print("r  = 0x%032x" % r)
    cr = clamp_r(r)
    print("cr = 0x%0x32" % cr)


#-------------------------------------------------------------------
#-------------------------------------------------------------------
def test_gen_poly1305_tag():
    key = [0x01] * 32
    message = [0x55, 0xaa] * 60
    my_tag = gen_poly1305_tag(key, message)
    result = verify_poly1305_tag(key, message, my_tag)


#-------------------------------------------------------------------
# main()
#
# Run Poly1305 tests.
#-------------------------------------------------------------------
def main():
    print("Testing Poly1305")
    slist = [0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
             0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b]
    s = b2le(slist)
    print("s = 0x%032x" % s)

    test_clamp_r()


#-------------------------------------------------------------------
#-------------------------------------------------------------------
if __name__=="__main__":
    sys.exit(main())

#=======================================================================
# EOF poly1305_test.py
#=======================================================================
