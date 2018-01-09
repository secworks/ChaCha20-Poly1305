# ChaCha20-Poly1305 #
Hardware implementation of the ChaCha20-Poly1305 AEAD construction


## Introduction ##
This is a hardware implementation of the Authenticated Encryption
construction ChaCha20-Poly1305. The functionality matches the
description in
[RFC 7539](https://tools.ietf.org/html/rfc7539 "RFC 7359 - ChaCha20 and Poly1305 for IETF Protocols")
and is needed for example for the
[TLS and DTLS cipher suites in RFC 7905](https://tools.ietf.org/html/rfc7905 "RFC 7905 - ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)").


## Status ##
Not done.

The ChaCha core and integration is done. The Poly1305 implementation is
started, but is nowhere near completion. Right now it is modelling in
Python and architecture design.


## Implementation ##
The core is written in Verilog 2001 and is based around the
[ChaCha core](https://github.com/secworks/chacha).

The Poly1305 part of the core will (probably) have a processing cycle
time matching the ChaCha core.
