//======================================================================
//
// tb_chacha20_qr.v
// ----------------
// Testbench for the Chacha quarter round module. The test vector
// is from RFC 7539, chapter 2.1.1.
//
//
// Copyright (c) 2016, Assured AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or
// without modification, are permitted provided that the following
// conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module tb_chacha20_qr();

  //----------------------------------------------------------------
  // Register and Wire declarations.
  //----------------------------------------------------------------
  reg [31 : 0] tb_a;
  reg [31 : 0] tb_b;
  reg [31 : 0] tb_c;
  reg [31 : 0] tb_d;
  wire [31 : 0] tb_a_prim;
  wire [31 : 0] tb_b_prim;
  wire [31 : 0] tb_c_prim;
  wire [31 : 0] tb_d_prim;


  //----------------------------------------------------------------
  // dut
  //----------------------------------------------------------------
  chacha_qr dut(
                .a(tb_a),
                .b(tb_b),
                .c(tb_c),
                .d(tb_d),

                .a_prim(tb_a_prim),
                .b_prim(tb_b_prim),
                .c_prim(tb_c_prim),
                .d_prim(tb_d_prim)
               );


  //----------------------------------------------------------------
  // chacha20_core_test
  //----------------------------------------------------------------
  initial
    begin : chacha20_core_test
      $display("   -- Testbench for chacha quarterround started --");
      $display("");

      // Assign vector and wait a delta.
      tb_a = 32'h11111111;
      tb_b = 32'h01020304;
      tb_c = 32'h9b8d6f43;
      tb_d = 32'h01234567;
      #1

      $display("a = 0x%08x b = 0x%08x c = 0x%08x d = 0x%08x",
               tb_a, tb_b, tb_c, tb_d);
      $display("a = 0x%08x b = 0x%08x c = 0x%08x d = 0x%08x",
               tb_a_prim, tb_b_prim, tb_c_prim, tb_d_prim);

      if ((tb_a_prim == 32'hea2a92f4) && (tb_b_prim == 32'hcb1cf8ce) &&
          (tb_c_prim == 32'h4581472e) &&(tb_d_prim == 32'h5881c4bb))
        $display("*** QR generates correct result.");
      else
        $display("*** QR generates incorrect result.");

      $display("*** chacha quarterround simulation done ***");
      $finish;
    end // chacha20_core_test

endmodule // tb_chacha20_core

//======================================================================
// EOF tb_chacha20_core.v
//======================================================================
