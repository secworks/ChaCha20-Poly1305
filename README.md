# ChaCha20-Poly1305 #
Hardware implementation of the ChaCha20-Poly1305 AEAD construction


## Introduction ##
This is a hardware implementation of the Authenticated Encryption
construction ChaCha20-Poly1305. The functionality matches the
description in
[RFC 7539][https://tools.ietf.org/html/rfc7539 "RFC 7359 - ChaCha20 and Poly1305 for IETF Protocols"]
and is needed for example for the
[TLS and DTLS cipher suites in RFC 7905][https://tools.ietf.org/html/rfc7905 "RFC 7905 - ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)"].


## Implementation ##
The core is written in Verilog 2001 and is based around the
[ChaCha core][https://github.com/secworks/chacha].


## Status ##

***(2016-06-23)***

Core implementation started.
