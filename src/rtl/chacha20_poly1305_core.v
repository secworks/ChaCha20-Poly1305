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
                              input wire [255 : 0]  key,
                              input wire [095 : 0]  nonce,
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

  localparam R_CLAMP  = 128'h0ffffffc0ffffffc0ffffffc0fffffff;
  localparam POLY1305 = 130'h3fffffffffffffffffffffffffffffffb;


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg [127 : 0] r_reg;
  reg [127 : 0] r_new;
  reg           r_we;

  reg [127 : 0] s_reg;
  reg [127 : 0] s_new;
  reg           s_we;

  reg [255 : 0] acc_reg;
  reg [255 : 0] acc_new;
  reg           acc_we;

  reg [2 : 0] core_ctrl_reg;
  reg [2 : 0] core_ctrl_new;
  reg         core_ctrl_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg tmp_ready;
  reg tmp_valid;

  reg          core_init;
  reg          core_next;
  wire         core_ready;
  wire         core_data_valid;
  wire         core_keylen;
  wire [4 : 0] core_rounds;
  reg [31 : 0] core_init_ctr;

  reg poly1305_keygen;
  reg poly1305_init;
  reg poly1305_next;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign ready = tmp_ready;
  assign valid = tmp_valid;

  // Always 256 bit keys and 20 rounds.
  assign core_keylen = 1;
  assign core_rounds = 5'h14;


  //----------------------------------------------------------------
  // core instantiation.
  //----------------------------------------------------------------
  chacha_core core(
                   .clk(clk),
                   .reset_n(reset_n),

                   .init(core_init),
                   .next(core_next),
                   .key(key),
                   .keylen(core_keylen),
                   .iv(nonce[095 : 032]),
                   .ctr({nonce[31 : 0], core_init_ctr}),
                   .rounds(core_rounds),
                   .data_in(data_in),

                   .ready(core_ready),
                   .data_out(data_out),
                   .data_out_valid(core_data_valid)
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
          r_reg         <= 128'h0;
          s_reg         <= 128'h0;
          acc_reg       <= 256'h0;
          core_ctrl_reg <= CTRL_IDLE;
        end
      else
        begin
          if (r_we)
            r_reg <= r_new;

          if (s_we)
            s_reg <= s_new;

          if (acc_we)
            acc_reg <= acc_new;

          if (core_ctrl_we)
            core_ctrl_reg <= core_ctrl_new;
        end
    end // reg_update


  //----------------------------------------------------------------
  // chacha_mux
  //
  // Since we use the chacha core both to encrypt/decrypt
  // and generate the poly1305 key we need to have a mux
  // in front of the core.
  //----------------------------------------------------------------
  always @*
    begin : chacha_mux
      if (poly1305_keygen)
        begin

        end
      else
        begin

        end
    end

  //----------------------------------------------------------------
  // poly1305_dp
  //
  // The datapath for implementing poly1305. We need logic
  // to init the accumulator and setting the r, s keys. We need
  // logic to either update the accumulator from cleartext
  // or calculated ciphertext.
  //----------------------------------------------------------------
  always @*
    begin : poly1305_dp
      reg [512 : 0] block;

      acc_new = 256'h0;
      acc_we  = 0;
      r_new   = data_out[255 : 128] & R_CLAMP;
      r_we    = 0;
      s_new   = data_out[127 : 000];
      s_we    = 0;

      if (poly1305_init)
        begin
          r_we   = 1;
          s_we   = 1;
          acc_we = 1;
        end

      if (poly1305_next)
        begin
          if (encdec)
            block = {1'h1, data_out};
          else
            block = {1'h1, data_in};

          acc_new = ((acc_reg + block) * r_reg) % POLY1305;
          acc_we  = 1;
        end
    end


  //----------------------------------------------------------------
  // core_ctrl
  //
  // Main control FSM.
  //----------------------------------------------------------------
  always @*
    begin : core_ctrl
      tmp_ready    = 0;
      tmp_valid    = 0;
      core_init    = 0;
      core_next    = 0;

      poly1305_keygen = 0;
      poly1305_init   = 0;
      poly1305_next   = 0;

      core_init_ctr = 32'h0;
      core_ctrl_new = CTRL_IDLE;
      core_ctrl_we  = 0;

      case (core_ctrl_reg)
        CTRL_IDLE:
          begin
            if (init)
              begin
                core_ctrl_new = CTRL_INIT;
                core_ctrl_we  = 1;
              end
          end

        CTRL_INIT:
          begin
            core_ctrl_new = CTRL_IDLE;
            core_ctrl_we  = 1;
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
