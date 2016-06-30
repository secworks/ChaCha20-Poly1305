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
  localparam CONFIG_ENCDEC_BIT      = 0;

  localparam ADDR_INIT_CTR          = 8'h0c;

  localparam ADDR_KEY0              = 8'h10;
  localparam ADDR_KEY7              = 8'h17;

  localparam ADDR_IV0               = 8'h20;
  localparam ADDR_IV2               = 8'h22;

  localparam ADDR_DATA0             = 8'h40;
  localparam ADDR_DATA15            = 8'h4f;

  localparam ADDR_TAG0              = 8'h50;
  localparam ADDR_TAG3              = 8'h53;

  localparam CORE_NAME0             = 32'h63323070; // "c20p"
  localparam CORE_NAME1             = 32'h31333035; // "1305"
  localparam CORE_VERSION           = 32'h302e3031; // "1.01"


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg init_reg;
  reg next_reg;
  reg done_reg;

  reg encdec_reg;
  reg encdec_we;

  reg [31 : 0] init_ctr_reg;
  reg          init_ctr_we;

  reg [31 : 0] key_reg [0 : 7];
  reg          key_we;

  reg [31 : 0] iv_reg [0 : 2];
  reg          iv_we;

  reg [31 : 0] data_reg [0 : 15];
  reg          data_we;

  reg [4 : 0] rounds_reg;
  reg         rounds_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [31 : 0]   tmp_read_data;

  wire           core_ready;
  wire           core_valid;
  wire           core_tag_ok;
  wire [255 : 0] core_key;
  wire [095 : 0] core_iv;
  wire [511 : 0] core_data_in;
  wire [511 : 0] core_data_out;
  wire [127 : 0] core_tag;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign core_key = {key_reg[0], key_reg[1], key_reg[2], key_reg[3],
                     key_reg[4], key_reg[5], key_reg[6], key_reg[7]};

  assign core_iv = {iv_reg[0], iv_reg[1], iv_reg[2]};

  assign core_data_in = {data_reg[00], data_reg[01], data_reg[02], data_reg[03],
                         data_reg[04], data_reg[05], data_reg[06], data_reg[07],
                         data_reg[08], data_reg[09], data_reg[10], data_reg[11],
                         data_reg[12], data_reg[13], data_reg[14], data_reg[15]};


  //----------------------------------------------------------------
  // core instantiation.
  //----------------------------------------------------------------
  chacha20_poly1305_core core(
                              .clk(clk),
                              .reset_n(reset_n),

                              .init(init_reg),
                              .next(next_reg),
                              .done(done_reg),

                              .encdec(encdec_reg),
                              .init_ctr(init_ctr_reg),
                              .key(core_key),
                              .iv(core_iv),
                              .data_in(core_data_in),

                              .ready(core_ready),
                              .valid(core_valid),
                              .tag_ok(core_tag_ok),
                              .data_out(core_data_out),
                              .tag(core_tag)
                             );


  //----------------------------------------------------------------
  // reg_update
  //
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with synchronous
  // active low reset.
  //----------------------------------------------------------------
  always @ (posedge clk)
    begin : reg_update
      integer i;

      if (!reset_n)
        begin
          init_reg     <= 0;
          next_reg     <= 0;
          done_reg     <= 0;
          encdec_reg   <= 0;
          init_ctr_reg <= 32'h0;
          iv_reg[0]    <= 32'h0;
          iv_reg[1]    <= 32'h0;
          iv_reg[2]    <= 32'h0;

          for (i = 0 ; i < 8 ; i = i + 1)
            begin
              key_reg[i] <= 32'h0;
              data_reg[i] <= 32'h0;
              data_reg[(i + 8)] <= 32'h0;
            end
        end
      else
        begin
          init_reg <= init_new;
          next_reg <= next_new;
          done_reg <= done_new;

          if (encdec_we)
            encdec_reg <= write_data[0];

          if (init_ctr_we)
            init_ctr_reg <= write_data;

          if (key_we)
            key_reg[address[2 : 0]] <= write_data;

          if (iv_we)
            iv_reg[address[1 : 0]] <= write_data;

          if (data_we)
            data_reg[address[3 : 0]] <= write_data;
        end
    end // reg_update


  //----------------------------------------------------------------
  // Address decoder logic.
  //----------------------------------------------------------------
  always @*
    begin : addr_decoder
      init_new    = 0;
      next_new    = 0;
      done_new    = 0;
      encdec_we   = 0;
      init_ctr_we = 0;
      key_we      = 0;
      iv_we       = 0;
      data_we     = 0;

      tmp_read_data = 32'h0;

      if (cs)
        begin
          if (we)
            begin
              if (address == ADDR_CTRL)
                begin
                  init_new = write_data[CTRL_INIT_BIT];
                  next_new = write_data[CTRL_NEXT_BIT];
                  done_new = write_data[CTRL_DONE_BIT];
                end

              if (address == ADDR_CONFIG)
                begin
                  encdec_we = 1;
                end

              if (address == ADDR_INIT_CTR)
                init_ctr_we = 1;

              if ((address >= ADDR_KEY0) && (address <= ADDR_KEY7))
                key_we = 1;

              if ((address >= ADDR_IV0) && (address <= ADDR_IV2))
                iv_we = 1;

              if ((address >= ADDR_DATA0) && (address <= ADDR_DATA15))
                data_we = 1;
            end

          else
            begin
              if (address == ADDR_NAME0)
                tmp_read_data = CORE_NAME0;

              if (address == ADDR_NAME1)
                tmp_read_data = CORE_NAME1;

              if (address == ADDR_VERSION)
                tmp_read_data = CORE_VERSION;

              if (address == ADDR_CTRL)
                tmp_read_data = {29'h0, done_reg, next_reg, init_reg};

              if (address == ADDR_STATUS)
                tmp_read_data = {29'h0, tag_ok_reg, data_out_valid_reg, ready_reg};

              if (address == ADDR_CONFIG)
                tmp_read_data = {31'h0, encdec_reg};

              if (address == ADDR_INIT_CTR)
                tmp_read_data = init_ctr_reg;

              if ((address >= ADDR_KEY0) && (address <= ADDR_KEY7))
                tmp_read_data = key_reg[address[2 : 0]];

              if ((address >= ADDR_IV0) && (address <= ADDR_IV2))
                tmp_read_data = iv_reg[address[2 : 0]];

              if ((address >= ADDR_DATA0) && (address <= ADDR_DATA15))
                // TODO: Add slicing.
                tmp_read_data = 32'hf;

              if ((address >= TAG00) && (address <= ADDR_TAG3))
                // TODO: Add slicing.
                tmp_read_data = 32'ha;
            end
        end
    end // addr_decoder
endmodule // chacha_poly1305

//======================================================================
// EOF chacha_poly1305.v
//======================================================================
