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
NUM_DOUBLEROUNDS = 10

#-------------------------------------------------------------------
#-------------------------------------------------------------------
# Helper functions.
#-------------------------------------------------------------------
#-------------------------------------------------------------------


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
# lw32l()
#
# Convert a given list of 32-bit little endian words to a
# list of bytes.
#-------------------------------------------------------------------
def lw32l(wlist):
    blists = [[(w & 0xff), ((w >> 8) & 0xff), ((w >> 16) & 0xff),
                   (w >> 24)] for w in wlist]
    return wlists


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


#-------------------------------------------------------------------
#-------------------------------------------------------------------
# Tested functions.
#-------------------------------------------------------------------
#-------------------------------------------------------------------

#-------------------------------------------------------------------
# qr()
#
# The ChaCha qr function.
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
# quarterround()
#
# Update the given state by applying the qr function on the
# given elements in the state.
#-------------------------------------------------------------------
def quarterround(state, ai, bi, ci, di):
    (ap, bp, cp, dp) = qr(state[ai], state[bi], state[ci], state[di])
    state[ai] = ap
    state[bi] = bp
    state[ci] = cp
    state[di] = dp
    return state


#-------------------------------------------------------------------
# doubleround()
#
# Perform the ChaCha doubleround on the given state by applying
# eigth specific quarterrounds.
#-------------------------------------------------------------------
def doubleround(state):
    quarterround(state, 0, 4, 8,12)
    quarterround(state, 1, 5, 9,13)
    quarterround(state, 2, 6,10,14)
    quarterround(state, 3, 7,11,15)
    quarterround(state, 0, 5,10,15)
    quarterround(state, 1, 6,11,12)
    quarterround(state, 2, 7, 8,13)
    quarterround(state, 3, 4, 9,14)
    return state


#-------------------------------------------------------------------
# chacha_block()
#
# The chacha block function. Given a 256 bit key, 32 bit counter
# and 96 bit nonce will create a state and then update the state
# for 10 doublerounds. Finally the finalized state is returned
# as a sequence of bytes.
#
# This code follows the pseudo code in 2.3.1 in RFC 7539.
#-------------------------------------------------------------------
def chacha_block(key, counter, nonce):
    state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                 key[0],     key[1],     key[2],     key[3],
                 key[4],     key[5],     key[6],     key[7],
                counter,   nonce[0],   nonce[1],   nonce[2]]

    print_chacha_state(state)

    working_state = state[:]
    for i in range(NUM_DOUBLEROUNDS):
        working_state = doubleround(working_state)

    print_chacha_state(working_state)
    for i in range(len(state)):
        state[i] = (state[i] + working_state[i]) & 0xffffffff
    print_chacha_state(state)
    return state


#-------------------------------------------------------------------
#-------------------------------------------------------------------
# Tests.
#-------------------------------------------------------------------
#-------------------------------------------------------------------

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
# run_qr_chacha_state_test()
#
# Test the quarterround function applied to the chacha state.
# Test vectors from chapter 2.2.1 in RFC 7539.
#-------------------------------------------------------------------
def run_qr_chacha_state_test():
    chacha_state = [0] * 16

    init_state = [0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
                  0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
                  0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
                  0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320]

    expected_state = [0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
                      0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
                      0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
                      0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320]

    print("ChaCha quarterround update test.")
    print("ChaCha state after init:")
    for i in range(len(init_state)):
        chacha_state[i] = init_state[i]
    print_chacha_state(chacha_state)

    print("ChaCha state after quarterround(2, 7, 8, 13):")
    chacha_state = quarterround(chacha_state, 2, 7, 8, 13)
    print_chacha_state(chacha_state)
    check_chacha_state(chacha_state, expected_state)


#-------------------------------------------------------------------
# run_chacha_doubleround_function_test()
#
# Test the chacha doubleround function applied 10 times
# on the chacha state.
# Test vectors from chapter 2.3.2 in RFC 7539.
#-------------------------------------------------------------------
def run_chacha_doubleround_function_test():
    init_state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                  0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                  0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                  0x00000001, 0x09000000, 0x4a000000, 0x00000000]

    expected_state = [0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f,
                      0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7,
                      0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd,
                      0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2]

    chacha_state = [0] * 16
    for i in range(len(init_state)):
        chacha_state[i] = init_state[i]
    print("ChaCha state after init:")
    print_chacha_state(chacha_state)

    print("ChaCha state updates for 10 doublerounds:")
    for i in range(10):
        chacha_state = doubleround(chacha_state)
        print("After round %02d:" % (i + 1))
        print_chacha_state(chacha_state)

    check_chacha_state(chacha_state, expected_state)


#-------------------------------------------------------------------
# run_chacha_block_test()
#-------------------------------------------------------------------
def run_chacha_block_test():
    expected_block = [0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
                      0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
                      0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
                      0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2]

    expected_bytes = [0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
                      0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
                      0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
                      0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
                      0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
                      0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
                      0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
                      0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e]

    key_bytes = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]
    key = l2lw32(key_bytes)

    nonce_bytes = [0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
                   0x00, 0x00, 0x00, 0x00]
    nonce = l2lw32(nonce_bytes)

    counter = 0x0000001

    block = chacha_block(key, counter, nonce)
    check_chacha_state(block, expected_block)


#-------------------------------------------------------------------
# main()
#
# Run chacha tests.
#-------------------------------------------------------------------
def main():
#    run_rotl_test()
#    run_qr_test()
#    run_qr_chacha_state_test()
#    run_chacha_doubleround_function_test()
    run_chacha_block_test()


#-------------------------------------------------------------------
#-------------------------------------------------------------------
if __name__=="__main__":
    sys.exit(main())

#=======================================================================
# EOF chacha_test.py
#=======================================================================
