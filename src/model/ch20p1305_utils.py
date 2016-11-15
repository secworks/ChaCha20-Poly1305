#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#=======================================================================
#
# utils.py
# --------
# Utility functions used by the ChaCha20, Poly1305 and the
# ChaCha20-Poly1306 models.
#
#
# Copyright (c) 2016 Secworks Sweden AB
# Author: Joachim Strömbergson
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
# 1. Redistributions of source code must rettain the above copyright
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


#-------------------------------------------------------------------
# print_bytelist()
#-------------------------------------------------------------------
def print_bytelist(pad, bl):
    for i in range(len(bl)):
        if i > 0 and (i % 8 == 0):
            print("\n" + " " * pad, end="")
        print("0x%02x " % bl[i], end="")
    print()


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
# check_bytelists()
#
# Chack if a given list of bytes matches the expected list of
# bytes given.
#-------------------------------------------------------------------
def check_bytelists(bytelist, expected_bytelist):
    if len(bytelist) != len(expected_bytelist):
        print("Error: Length of bytelist does not match length of expected bytelist.")
        return

    errors = 0
    for i in range(len(bytelist)):
        if bytelist[i] != expected_bytelist[i]:
            errors += 1
    if errors > 0:
        print("Error: bytelist does not match expected bytelist.")
        print(bytelist)
        print(expected_bytelist)
    else:
        print("Bytelist is correct.")
    print("")


#-------------------------------------------------------------------
# print_chacha_state()
#
# Print the given chacha state matrix.
#-------------------------------------------------------------------
def print_chacha_state(state):
    print("0x%08x 0x%08x 0x%08x 0x%08x" % (state[00], state[1],  state[2],  state[3]))
    print("0x%08x 0x%08x 0x%08x 0x%08x" % (state[4],  state[5],  state[6],  state[7]))
    print("0x%08x 0x%08x 0x%08x 0x%08x" % (state[8],  state[9],  state[10], state[11]))
    print("0x%08x 0x%08x 0x%08x 0x%08x" % (state[12], state[13], state[14], state[15]))
    print("")


#-------------------------------------------------------------------
# check_chacha_state()
#
# Check a givem chacha state against the given expected state.
# Report if state is correct, or which elements are incorrect.
#-------------------------------------------------------------------
def check_chacha_state(state, expected):
    errors = 0
    for i in range(len(state)):
        if state[i] != expected[i]:
            print("state[%02d] = 0x%08x does not match expected 0x%08x" %
                      (i, state[i], expected[i]))
            errors += 1

    if (errors > 0):
        print("State is incorrect at %02d elements" % errors)
    else:
        print("State is correct.")
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
# w32bl()
#
# Convert a given list of 32-bit little endian words to a
# list of bytes.
#-------------------------------------------------------------------
def w32bl(wlist):
    blists = [[(w & 0xff), ((w >> 8) & 0xff), ((w >> 16) & 0xff),
                   (w >> 24)] for w in wlist]
    merged_blist = []
    for chunk in blists:
        merged_blist.append(chunk[0])
        merged_blist.append(chunk[1])
        merged_blist.append(chunk[2])
        merged_blist.append(chunk[3])
    return merged_blist


#-------------------------------------------------------------------
# l2lw32()
#
# Convert a given list of bytes to list of little endian
# 32-bit endian words.
#-------------------------------------------------------------------
def l2lw32(bytelist):
    num_words = int(len(bytelist) / 4)
    chunks = [bytelist[(i * 4) : (i*4 + 4)] for i in range(num_words)]
    return [((b[3] << 24) + (b[2] << 16) + (b[1] << 8) + b[0]) for b in chunks]

#=======================================================================
# EOF utils.py
#=======================================================================
