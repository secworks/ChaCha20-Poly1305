#===================================================================
#
# Makefile
# --------
# Makefile for building the chacha_poly1305 core and
# top simulation targets. There is also support for linting.
#
#
# Copyright (c) 2016, Secworks Sweden AB
# Joachim Strömbergson
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
#===================================================================

CHACHA_QR_SRC =../../chacha/src/rtl/chacha_qr.v
CHACHA_CORE_SRC =../../chacha/src/rtl/chacha_core.v $(CHACHA_QR_SRC)
CORE_SRC =../src/rtl/chacha20_poly1305_core.v $(CHACHA_CORE_SRC)
TOP_SRC =../src/rtl/chacha20_poly1305.v $(CORE_SRC)

CHACHA_CORE_TB_SRC = ../src/tb/tb_chacha20_core.v
CHACHA_QR_TB_SRC = ../src/tb/tb_chacha20_qr.v

CORE_TB_SRC =../src/tb/tb_chacha20_poly1305_core.v
TOP_TB_SRC =../src/tb/tb_chacha20_poly1305.v

CC=iverilog
CC_FLAGS= -Wall

LINT=verilator
LINT_FLAGS = +1364-2001ext+ --lint-only  -Wall -Wno-fatal -Wno-DECLFILENAME


all: top.sim chacha.sim qr.sim


top.sim: $(TOP_TB_SRC) $(TOP_SRC)
	$(CC) $(CC_FLAGS) -o top.sim $(TOP_TB_SRC) $(TOP_SRC)


core.sim: $(CORE_TB_SRC) $(CORE_SRC)
	$(CC) $(CC_FLAGS) -o core.sim $(CORE_TB_SRC) $(CORE_SRC)


chacha.sim: $(CHACHA_CORE_TB_SRC) $(CHACHA_CORE_SRC)
	$(CC) $(CC_FLAGS) -o chacha.sim $(CHACHA_CORE_TB_SRC) $(CHACHA_CORE_SRC)


qr.sim: $(CHACHA_QR_TB_SRC) $(CHACHA_QR_SRC)
	$(CC) $(CC_FLAGS) -o qr.sim $(CHACHA_QR_TB_SRC) $(CHACHA_QR_SRC)


sim-core: core.sim
	./core.sim


sim-top: top.sim
	./top.sim


sim-chacha: chacha.sim
	./chacha.sim


sim-qr: qr.sim
	./qr.sim


lint:  $(TOP_SRC)
	$(LINT) $(LINT_FLAGS) $(TOP_SRC)



clean:
	rm -f core.sim
	rm -f top.sim
	rm -f chacha.sim
	rm -f qr.sim


help:
	@echo "Supported targets:"
	@echo "------------------"
	@echo "all:        Build all simulation targets."
	@echo "top:        Build the top simulation target."
	@echo "core:       Build the top simulation target."
	@echo "sim-top:    Run top simulation."
	@echo "sim-core:   Run core simulation."
	@echo "sim-chacha: Run chacha core simulation."
	@echo "sim-qr:     Run qr simulation."
	@echo "lint:       Lint the source."
	@echo "clean:      Remove build targets."

#===================================================================
# EOF Makefile
#===================================================================
