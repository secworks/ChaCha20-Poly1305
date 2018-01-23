//======================================================================
//
// mulacc_test.v
// -------------
// Test implementation of a slice of the mult function. Just to see
// what a naive implementation would require. Note that we have a big
// API just to allow us to build the functionality in a FPGA.
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

module mulacc_test(
                   input wire           clk,
                   input wire           reset_n,

                   input wire           cs,
                   input wire           we,
                   input wire  [5 : 0]  address,
                   input wire  [25 : 0] write_data,
                   output wire [58 : 0] read_data
                   );

  //----------------------------------------------------------------
  // Defines. For the API.
  //----------------------------------------------------------------
  localparam ADDR_A0   = 8'h00;
  localparam ADDR_A4   = 8'h04;
  localparam ADDR_B0   = 8'h10;
  localparam ADDR_B4   = 8'h14;
  localparam ADDR_RES0 = 8'h20;
  localparam ADDR_RES4 = 8'h24;


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg [25 : 0] a_mem [0 : 4];
  reg          a_mem_we;
  reg [25 : 0] b_mem [0 : 4];
  reg          b_mem_we;

  reg [58 : 0] p0_reg;
  reg [58 : 0] p0_new;

  reg [28 : 0] b51_reg;
  reg [28 : 0] b51_new;
  reg [28 : 0] b52_reg;
  reg [28 : 0] b52_new;
  reg [28 : 0] b53_reg;
  reg [28 : 0] b53_new;
  reg [28 : 0] b54_reg;
  reg [28 : 0] b54_new;

  reg [53 : 0] prim0_reg;
  reg [53 : 0] prim0_new;
  reg [53 : 0] prim1_reg;
  reg [53 : 0] prim1_new;
  reg [53 : 0] prim2_reg;
  reg [53 : 0] prim2_new;
  reg [53 : 0] prim3_reg;
  reg [53 : 0] prim3_new;
  reg [53 : 0] prim4_reg;
  reg [53 : 0] prim4_new;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [58 : 0] tmp_read_data;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign read_data = tmp_read_data;


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
          b51_reg   <= 29'h0;
          b52_reg   <= 29'h0;
          b53_reg   <= 29'h0;
          b54_reg   <= 29'h0;
          prim0_reg <= 54'h0;
          prim1_reg <= 54'h0;
          prim2_reg <= 54'h0;
          prim3_reg <= 54'h0;
          prim4_reg <= 54'h0;
          p0_reg    <= 59'h0;
        end
      else
        begin
          b51_reg <= b51_new;
          b52_reg <= b52_new;
          b53_reg <= b53_new;
          b54_reg <= b54_new;

          prim0_reg <= prim0_new;
          prim1_reg <= prim1_new;
          prim2_reg <= prim2_new;
          prim3_reg <= prim3_new;
          prim4_reg <= prim4_new;

          p0_reg <= p0_new;

          if (a_mem_we)
            a_mem[address[2:0]] <= write_data;

          if (b_mem_we)
            b_mem[address[2:0]] <= write_data;
        end
    end // reg_update


  //----------------------------------------------------------------
  // mac_logic
  //----------------------------------------------------------------
  always @*
    begin : mac_logic
      reg [28 : 0] b51;
      reg [28 : 0] b52;
      reg [28 : 0] b53;
      reg [28 : 0] b54;

      // Fix the fixed mult by five operands.
      b51_new = {b_mem[1], 2'b0} + b_mem[1];
      b52_new = {b_mem[2], 2'b0} + b_mem[2];
      b53_new = {b_mem[3], 2'b0} + b_mem[3];
      b54_new = {b_mem[4], 2'b0} + b_mem[4];

      // Perform multiplications.
      prim0_new = a_mem[0] * b_mem[0];
      prim1_new = a_mem[1] * b54_reg;
      prim2_new = a_mem[2] * b53_reg;
      prim3_new = a_mem[3] * b52_reg;
      prim4_new = a_mem[4] * b51_reg;

      // Peform final additions of products.
      p0_new = prim0_reg + prim1_reg + prim2_reg +
               prim3_reg + prim4_reg;
    end


  //----------------------------------------------------------------
  // Address decoder logic.
  //----------------------------------------------------------------
  always @*
    begin : addr_decoder
      a_mem_we      = 0;
      b_mem_we      = 0;
      tmp_read_data = 59'h0;

      if (cs)
        begin
          if (we)
            begin
              if ((address >= ADDR_A0) && (address <= ADDR_A4))
                a_mem_we = 1;

              if ((address >= ADDR_B0) && (address <= ADDR_B4))
                b_mem_we = 1;
            end

          else
            begin
              if ((address >= ADDR_RES0) && (address <= ADDR_RES4))
                tmp_read_data = p0_reg;
            end
        end
    end // addr_decoder

endmodule // poly1305_mulacc

//======================================================================
// EOF poly1305_mulacc.v
//======================================================================
