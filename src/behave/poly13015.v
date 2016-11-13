//======================================================================
//
// poly1305.v
// ----------
// Poly1305 Verilog behavioral model.
//
//
// Copyright (c) 2016, Secworks Sweden AB
// Joachim Strömbergson
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

module poly1305();
  reg [127 : 0] r_reg;


  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam R_CLAMP  = 128'h0ffffffc0ffffffc0ffffffc0fffffff;
  localparam POLY1305 = 134'h3fffffffffffffffffffffffffffffffb;


  //----------------------------------------------------------------
  // poly1305_init()
  //----------------------------------------------------------------
  task poly1305_init(input [127 : 0] key);
    begin
      r_reg = key & R_CLAMP;
    end
  endtask // poly1305_init


  //----------------------------------------------------------------
  // poly1305_init()
  //----------------------------------------------------------------
  task poly1305_update(input [127 : 0] block);
    begin

    end
  endtask // poly1305_init


  //----------------------------------------------------------------
  // poly1305_tests
  //----------------------------------------------------------------
  initial
    begin : poly1305_tests
      reg [127 : 0] key;

      // Check that we correctly clamp given a key.
      key = 128'h85d6be7857556d337f4452fe42d506a8;
      poly1305_init(key);
      $display("r: 0x%032x", r_reg);
    end // poly1305_tests

endmodule // poly1305

//======================================================================
// EOF poly1305
//======================================================================
