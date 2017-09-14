#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#=======================================================================
#
# poly1305.py
# -----------
# Test implementation of poly1305. Basically a Python version
# of the code presented at:
# http://loup-vaillant.fr/tutorials/poly1305-design
#
#
# Copyright (c) 2017 Secworks Sweden AB
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
VERBOSE = False

MAX64 = 2**64 - 1

#-------------------------------------------------------------------
# poly_mul()
#
# Multiplies h and r, put the result in h
#-------------------------------------------------------------------
def poly_mul(h, r):
    # Clamp r.
    r0 = r[0];
    r1 = r[1];
    r2 = r[2];
    r3 = r[3];
    rr0 = (r[0] >> 2) * 5
    rr1 = (r[1] >> 2) * 5
    rr2 = (r[2] >> 2) * 5
    rr3 = (r[3] >> 2) * 5

    # school book modular multiplication (without carry propagation)
    x0 = (h[0] * r0 + h[1] * rr3 + h[2] * rr2 + h[3] * rr1 + h[4] * rr0) % MAX64
    x1 = (h[0] * r1 + h[1] * r0  + h[2] * rr3 + h[3] * rr2 + h[4] * rr1) % MAX64
    x2 = (h[0] * r2 + h[1] * r1  + h[2] * r0  + h[3] * rr3 + h[4] * rr2) % MAX64
    x3 = (h[0] * r3 + h[1] * r2  + h[2] * r1  + h[3] * r0  + h[4] * rr3) % MAX64
    x4 = (h[4] * (r0 & 3)) % MAX64

    # carry propagation (put the result back in h)
    msb = x4 + (x3 >> 32)
    u = (msb >> 2) * 5
    u += (x0 & 0xffffffff)
    h[0] = u & 0xffffffff
    u >>= 32
    u += (x1 & 0xffffffff) + (x0 >> 32)
    h[1] = u & 0xffffffff
    u >>= 32
    u += (x2 & 0xffffffff) + (x1 >> 32)
    h[2] = u & 0xffffffff
    u >>= 32
    u += (x3 & 0xffffffff) + (x2 >> 32)
    h[3] = u & 0xffffffff
    u >>= 32
    u += msb & 3
    h[4] = u

    return h


#-------------------------------------------------------------------
# main()
#-------------------------------------------------------------------
def main():
    print("Poly 1305")
    my_h = [1, 0, 0, 0, 1]
    my_r = [0xffffffff, 0xaaaaaaaa, 0x55555555, 0x010101010101]
    print(poly_mul(my_h, my_r))


#-------------------------------------------------------------------
#-------------------------------------------------------------------
if __name__=="__main__":
    sys.exit(main())

#=======================================================================
# EOF poly1305.py
#=======================================================================
