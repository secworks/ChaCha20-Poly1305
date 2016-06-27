//======================================================================
//
// chacha_poly1305.v
// -----------------
// Top level wrapper for ChaCha20-Poly1305 AEAD cipher core.
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

module chacha20_poly1305(
                         input wire           clk,
                         input wire           reset_n,

                         input wire           cs,
                         input wire           we,
                         input wire  [7 : 0]  address,
                         input wire  [31 : 0] write_data,
                         output wire [31 : 0] read_data
                        );

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam ADDR_NAME0             = 8'h00;
  localparam ADDR_NAME1             = 8'h01;
  localparam ADDR_VERSION           = 8'h02;

  localparam ADDR_CTRL              = 8'h08;
  localparam CTRL_INIT_BIT          = 0;
  localparam CTRL_NEXT_BIT          = 1;
  localparam CTRL_DONE_BIT          = 2;

  localparam ADDR_STATUS            = 8'h09;
  localparam STATUS_READY_BIT       = 0;
  localparam STATUS_VALID_BIT       = 1;
  localparam STATUS_TAG_OK_BIT      = 2;

  localparam ADDR_CONFIG            = 8'h0a;
  localparam CONFIG_KEYLEN_BIT      = 0;
  localparam CONFIG_ROUNDS_LOW_BIT  = 4;
  localparam CONFIG_ROUNDS_HIGH_BIT = 8;

  localparam ADDR_KEY0              = 8'h10;
  localparam ADDR_KEY7              = 8'h17;

  localparam ADDR_IV0               = 8'h20;
  localparam ADDR_IV2               = 8'h21;

  localparam ADDR_INIT_CTR          = 8'h30;

  localparam ADDR_DATA_IN0          = 8'h40;
  localparam ADDR_DATA_IN15         = 8'h4f;

  localparam ADDR_DATA_OUT0         = 8'h50;
  localparam ADDR_DATA_OUT15        = 8'h5f;

  localparam ADDR_TAG_OUT0          = 8'h50;
  localparam ADDR_TAG_OUT3          = 8'h53;

  localparam CORE_NAME0     = 32'h63323070; // "c20p"
  localparam CORE_NAME1     = 32'h31333035; // "1305"
  localparam CORE_VERSION   = 32'h302e3031; // "1.01"


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg init_reg;
  reg next_reg;
  reg done_reg;

  reg ready_reg;
  reg valid_reg;
  reg tag_ok_reg;

  reg keylen_reg;
  reg keylen_we;

  reg [4 : 0] rounds_reg;
  reg         rounds_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [31 : 0]   tmp_read_data;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------


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
  // All registers are positive edge triggered with asynchronous
  // active low reset. All registers have write enable.
  //----------------------------------------------------------------
  always @ (posedge clk or negedge reset_n)
    begin
      if (!reset_n)
        begin

        end
      else
        begin

        end
    end // reg_update


  //----------------------------------------------------------------
  // Address decoder logic.
  //----------------------------------------------------------------
  always @*
    begin : addr_decoder
      init_new = 0;
      next_new = 0;
      done_new = 0;

      tmp_read_data = 32'h0;

      if (cs)
        begin
          if (we)
            begin
              case (address)
                ADDR_CTRL:
                  begin
                    init_new = write_data[CTRL_INIT_BIT];
                    next_new = write_data[CTRL_NEXT_BIT];
                    done_new = write_data[CTRL_DONE_BIT];
                  end

                default:
                  begin
                  end
              endcase
            end

          else
            begin
              case (address)
                ADDR_NAME0:
                  tmp_read_data = CORE_NAME0;
                ADDR_NAME1:
                  tmp_read_data = CORE_NAME1;
                ADDR_VERSION:
                  tmp_read_data = CORE_VERSION;

                ADDR_CTRL:
                  tmp_read_data = {29'h0, done_reg, next_reg, init_reg};

                ADDR_STATUS:
                  tmp_read_data = {29'h0, tag_ok_reg, data_out_valid_reg, ready_reg};

                ADDR_CONFIG:
                  tmp_read_data = {24'h0, rounds_reg, 3'h0, keylen_reg};

                default:
                  begin
                  end
              endcase // case (address)
            end
        end
    end // addr_decoder
endmodule // chacha_poly1305

//======================================================================
// EOF chacha_poly1305.v
//======================================================================
