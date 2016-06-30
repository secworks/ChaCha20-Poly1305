//======================================================================
//
// chacha_poly1305_core.v
// ----------------------
// Main core module for ChaCha20-Poly1305 AEAD cipher core.
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

module chacha20_poly1305_core(
                              input wire            clk,
                              input wire            reset_n,

                              input wire            init,
                              input wire            next,
                              input wire            done,
                              input wire            encdec,
                              input wire [031 : 0]  init_ctr,
                              input wire [255 : 0]  key,
                              input wire [095 : 0]  iv,
                              input wire [511 : 0]  data_in,

                              output wire           ready,
                              output wire           valid,
                              output wire           tag_ok,
                              output wire [511 : 0] data_out,
                              output wire [127 : 0] tag
                             );

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam CTRL_IDLE = 3'h0;
  localparam CTRL_INIT = 3'h1;

  localparam DEFAULT_CTR_INIT = 64'h00;

  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg [2 : 0] core_ctrl_reg;
  reg [2 : 0] core_ctrl_new;
  reg         core_ctrl_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign core_init    = 0;
  assign core_next    = 128'h0;
  assign ready        = 1;


  //----------------------------------------------------------------
  // core instantiation.
  //----------------------------------------------------------------
  chacha_core core(
                   .clk(clk),
                   .reset_n(reset_n),

                   .init(core_init),
                   .next(core_next),

                   .key(core_key),
                   .keylen(core_keylen),
                   .iv(core_iv),
                   .ctr(DEFAULT_CTR_INIT),
                   .rounds(core_rounds),

                   .data_in(core_data_in),

                   .ready(core_ready),

                   .data_out(core_data_out),
                   .data_out_valid(core_data_out_valid)
                  );


  //----------------------------------------------------------------
  // reg_update
  //
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with synchronous
  // active low reset.
  //----------------------------------------------------------------
  always @ (posedge clk)
    begin
      if (!reset_n)
        begin
          core_ctrl_reg <= CTRL_IDLE;
        end
      else
        begin
          if (core_ctrl_we)
            core_ctrl_reg <= core_ctrl_new;
        end
    end // reg_update


  //----------------------------------------------------------------
  // core_ctrl
  //
  // Main control FSM.
  //----------------------------------------------------------------
  always @*
    begin : core_ctrl
      core_ctrl = CTRL_IDLE;
      core_ctrl = 0;

      case (core_ctrl_reg)
        CTRL_IDLE:
          begin
            if (init)
              begin
                core_ctrl = CTRL_INIT;
                core_ctrl = 1;
              end
          end

        CTRL_INIT:
          begin
            core_ctrl = CTRL_IDLE;
            core_ctrl = 1;
          end

        default:
          begin
          end
      endcase // case (core_ctrl_reg)
    end // core_ctrl

endmodule // chacha_poly1305_core

//======================================================================
// EOF chacha_poly1305_core.v
//======================================================================
