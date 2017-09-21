//======================================================================
//
// poly1305_mulacc.v
// -----------------
// multiply-accumulate core used to implement the 128 bit
// multiplications in Poly1305.
//
//
// Copyright (c) 2017, Secworks Sweden AB
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

module poly1305_mulacc(
                       input wire           clk,
                       input wire           reset_n,

                       input wire           init,
                       input wire           update,
                       input wire  [63 : 0] opa,
                       input wire  [31 : 0] opb,
                       output wire [63 : 0] res
                      );

  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg [63 : 0] mulacc_res_reg;
  reg [63 : 0] mulacc_res_new;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign res = mulacc_res_reg;


  //----------------------------------------------------------------
  // reg_update
  //
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with synchronous
  // active low reset.
  //----------------------------------------------------------------
  always @ (posedge clk)
    begin : reg_update
      if (!reset_n)
        begin
          mulacc_res_reg <= 64'h0;
        end
      else
        begin
          if (update)
            mulacc_res_reg <= mulacc_res_new;
        end
    end // reg_update


  //----------------------------------------------------------------
  // mac_logic
  //----------------------------------------------------------------
  always @*
    begin : mac_logic
      reg [63 : 0] mul_res;
      reg [63 : 0] mux_addop;

      mul_res = opa * opb;

      if (init)
        mux_addop = 64'h0;
      else
        mux_addop = mulacc_res_reg;

      mulacc_res_new = mul_res + mux_addop;
    end

endmodule // poly1305_mulacc

//======================================================================
// EOF poly1305_mulacc.v
//======================================================================
