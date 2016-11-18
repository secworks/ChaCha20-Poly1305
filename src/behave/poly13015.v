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
  // Global Poly1305 state registers.
  reg [127 : 0] r_reg;
  reg [127 : 0] s_reg;
  reg [129 : 0] acc_reg;
  reg [127 : 0] tag_reg;

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam R_CLAMP  = 128'h0ffffffc0ffffffc0ffffffc0fffffff;
  localparam POLY1305 = 130'h3fffffffffffffffffffffffffffffffb;


  //----------------------------------------------------------------
  // poly1305_init()
  //
  // Initialize the internal Poly1305 state.
  //----------------------------------------------------------------
  task poly1305_init(input [255 : 0] key);
    begin : poly1305_init
      r_reg = key[255 : 128] & R_CLAMP;
      s_reg = key[127 :   0];
      acc_reg = 130'h0;
    end
  endtask // poly1305_init


  //----------------------------------------------------------------
  // poly1305_update()
  //
  // Given a block, update the internal Poly1305 state.
  //----------------------------------------------------------------
  task poly1305_update(input [129 : 0] block);
    begin : poly1305_update
      acc_reg = acc_reg + block;
      acc_reg = acc_reg * r_reg;
      acc_reg = acc_reg % POLY1305;
    end
  endtask // poly1305_init


  //----------------------------------------------------------------
  // poly1305_finalize()
  //----------------------------------------------------------------
  task poly1305_finalize;
    begin : poly1305_update
      acc_reg = acc_reg + s_reg;
      tag_reg = acc_reg[127 : 0];
    end
  endtask // poly1305_init


  //----------------------------------------------------------------
  // test poly1305_init()
  //----------------------------------------------------------------
  task test_poly1305_init;
    begin : test_poly1305_init
      reg [255 : 0] key;
      reg [127 : 0] expected;

      key = {128'ha806d542fe52447f336d555778bed685, 128'h0};
      expected = 128'h0806d5400e52447c036d555408bed685;

      poly1305_init(key);

      $display("key: 0x%064x", key);
      $display("r:   0x%032x", r_reg);
      if (r_reg == expected)
          $display("r is correct.");
      else
          $display("r is incorrect. Expexted 0x%0x32", expected);
    end
  endtask // poly1305_init


  //----------------------------------------------------------------
  // test poly1305_update()
  //----------------------------------------------------------------
  task test_poly1305_update;
    begin : test_poly1305_update
      reg [128 : 0] block;

      acc_reg = 130'h0;
      r_reg = 128'h0806d5400e52447c036d555408bed685;
      block = 129'h16f4620636968706172676f7470797243;
      poly1305_update(block);
      $display("acc after block1: 0x%033x", acc_reg);

      block = 129'h16f7247206863726165736552206d7572;
      poly1305_update(block);
      $display("acc after block2: 0x%033x", acc_reg);

      block = 129'h000000000000000000000000000017075;
      poly1305_update(block);
      $display("acc after block3: 0x%033x", acc_reg);
    end
  endtask // test_poly1305_update

  //----------------------------------------------------------------
  // poly1305_tests
  //----------------------------------------------------------------
  initial
    begin : poly1305_tests
      test_poly1305_init();
      test_poly1305_update();

    end // poly1305_tests

endmodule // poly1305

//======================================================================
// EOF poly1305
//======================================================================
