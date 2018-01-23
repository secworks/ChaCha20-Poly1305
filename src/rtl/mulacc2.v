//======================================================================
//
// mulacc2.v
// ---------
// Another experimental implementation. This time with a simple
// multiply-accumulate kernel. This kernel would be instantiated.
// and used iteratively in a Poly1305 core.
// Note that there are hold registers for the operands. In a real
// usage they would be outside of the kernel. They are here to get
// timing not dependent on the I/Os.
//
//
// Copyright (c) 2018, Assured AB
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

module mulacc2(
               input wire           clk,
               input wire           reset_n,

               input wire           clear,
               input wire           next,

               input wire [25 : 0]  a,
               input wire [28 : 0]  b,
               output wire [58 : 0] psum
              );


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg [25 : 0] a_reg;
  reg [28 : 0] b_reg;

  reg [58 : 0] psum_reg;
  reg [58 : 0] psum_new;
  reg          psum_we;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign psum = psum_reg;


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
          a_reg    <= 26'h0;
          b_reg    <= 29'h0;
          psum_reg <= 59'h0;
        end
      else
        begin
          a_reg <= a;
          b_reg <= b;

          if (psum_we)
            psum_reg <= psum_new;
        end
    end // reg_update


  //----------------------------------------------------------------
  // mac_logic
  //----------------------------------------------------------------
  always @*
    begin : mac_logic
      psum_new = 59'h0;
      psum_we  = 0;

      if (clear)
        begin
          psum_new = 59'h0;
          psum_we  = 1;
        end

      if (next)
        begin
          psum_new = (a_reg * b_reg) + psum_reg;
        end
    end

endmodule // poly1305_mulacc

//======================================================================
// EOF mulacc2.v
//======================================================================
