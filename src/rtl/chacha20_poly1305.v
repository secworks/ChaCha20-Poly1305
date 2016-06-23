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
  parameter ADDR_CTRL        = 8'h00;
  parameter CTRL_INIT_BIT    = 0;
  parameter CTRL_NEXT_BIT    = 1;

  parameter ADDR_STATUS      = 8'h01;
  parameter STATUS_READY_BIT = 0;

  parameter ADDR_KEYLEN      = 8'h08;
  parameter KEYLEN_BIT       = 0;
  parameter ADDR_ROUNDS      = 8'h09;
  parameter ROUNDS_HIGH_BIT  = 4;
  parameter ROUNDS_LOW_BIT   = 0;

  parameter ADDR_KEY0        = 8'h10;
  parameter ADDR_KEY1        = 8'h11;
  parameter ADDR_KEY2        = 8'h12;
  parameter ADDR_KEY3        = 8'h13;
  parameter ADDR_KEY4        = 8'h14;
  parameter ADDR_KEY5        = 8'h15;
  parameter ADDR_KEY6        = 8'h16;
  parameter ADDR_KEY7        = 8'h17;

  parameter ADDR_IV0         = 8'h20;
  parameter ADDR_IV1         = 8'h21;

  parameter ADDR_DATA_IN0    = 8'h40;
  parameter ADDR_DATA_IN1    = 8'h41;
  parameter ADDR_DATA_IN2    = 8'h42;
  parameter ADDR_DATA_IN3    = 8'h43;
  parameter ADDR_DATA_IN4    = 8'h44;
  parameter ADDR_DATA_IN5    = 8'h45;
  parameter ADDR_DATA_IN6    = 8'h46;
  parameter ADDR_DATA_IN7    = 8'h47;
  parameter ADDR_DATA_IN8    = 8'h48;
  parameter ADDR_DATA_IN9    = 8'h49;
  parameter ADDR_DATA_IN10   = 8'h4a;
  parameter ADDR_DATA_IN11   = 8'h4b;
  parameter ADDR_DATA_IN12   = 8'h4c;
  parameter ADDR_DATA_IN13   = 8'h4d;
  parameter ADDR_DATA_IN14   = 8'h4e;
  parameter ADDR_DATA_IN15   = 8'h4f;

  parameter ADDR_DATA_OUT0   = 8'h80;
  parameter ADDR_DATA_OUT1   = 8'h81;
  parameter ADDR_DATA_OUT2   = 8'h82;
  parameter ADDR_DATA_OUT3   = 8'h83;
  parameter ADDR_DATA_OUT4   = 8'h84;
  parameter ADDR_DATA_OUT5   = 8'h85;
  parameter ADDR_DATA_OUT6   = 8'h86;
  parameter ADDR_DATA_OUT7   = 8'h87;
  parameter ADDR_DATA_OUT8   = 8'h88;
  parameter ADDR_DATA_OUT9   = 8'h89;
  parameter ADDR_DATA_OUT10  = 8'h8a;
  parameter ADDR_DATA_OUT11  = 8'h8b;
  parameter ADDR_DATA_OUT12  = 8'h8c;
  parameter ADDR_DATA_OUT13  = 8'h8d;
  parameter ADDR_DATA_OUT14  = 8'h8e;
  parameter ADDR_DATA_OUT15  = 8'h8f;

  parameter DEFAULT_CTR_INIT = 64'h00;


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg init_reg;
  reg next_reg;
  reg ctrl_we;

  reg ready_reg;

  reg keylen_reg;
  reg keylen_we;

  reg [4 : 0] rounds_reg;
  reg         rounds_we;

  reg data_out_valid_reg;

  reg [31 : 0] key0_reg;
  reg          key0_we;
  reg [31 : 0] key1_reg;
  reg          key1_we;
  reg [31 : 0] key2_reg;
  reg          key2_we;
  reg [31 : 0] key3_reg;
  reg          key3_we;
  reg [31 : 0] key4_reg;
  reg          key4_we;
  reg [31 : 0] key5_reg;
  reg          key5_we;
  reg [31 : 0] key6_reg;
  reg          key6_we;
  reg [31 : 0] key7_reg;
  reg          key7_we;

  reg [31 : 0] iv0_reg;
  reg          iv0_we;
  reg [31 : 0] iv1_reg;
  reg          iv1_we;

  reg [31 : 0] data_in0_reg;
  reg          data_in0_we;
  reg [31 : 0] data_in1_reg;
  reg          data_in1_we;
  reg [31 : 0] data_in2_reg;
  reg          data_in2_we;
  reg [31 : 0] data_in3_reg;
  reg          data_in3_we;
  reg [31 : 0] data_in4_reg;
  reg          data_in4_we;
  reg [31 : 0] data_in5_reg;
  reg          data_in5_we;
  reg [31 : 0] data_in6_reg;
  reg          data_in6_we;
  reg [31 : 0] data_in7_reg;
  reg          data_in7_we;
  reg [31 : 0] data_in8_reg;
  reg          data_in8_we;
  reg [31 : 0] data_in9_reg;
  reg          data_in9_we;
  reg [31 : 0] data_in10_reg;
  reg          data_in10_we;
  reg [31 : 0] data_in11_reg;
  reg          data_in11_we;
  reg [31 : 0] data_in12_reg;
  reg          data_in12_we;
  reg [31 : 0] data_in13_reg;
  reg          data_in13_we;
  reg [31 : 0] data_in14_reg;
  reg          data_in14_we;
  reg [31 : 0] data_in15_reg;
  reg          data_in15_we;

  reg [31 : 0] data_out0_reg;
  reg [31 : 0] data_out1_reg;
  reg [31 : 0] data_out2_reg;
  reg [31 : 0] data_out3_reg;
  reg [31 : 0] data_out4_reg;
  reg [31 : 0] data_out5_reg;
  reg [31 : 0] data_out6_reg;
  reg [31 : 0] data_out7_reg;
  reg [31 : 0] data_out8_reg;
  reg [31 : 0] data_out9_reg;
  reg [31 : 0] data_out10_reg;
  reg [31 : 0] data_out11_reg;
  reg [31 : 0] data_out12_reg;
  reg [31 : 0] data_out13_reg;
  reg [31 : 0] data_out14_reg;
  reg [31 : 0] data_out15_reg;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  wire           core_init;
  wire           core_next;
  wire [255 : 0] core_key;
  wire           core_keylen;
  wire [4 : 0]   core_rounds;
  wire [63 : 0]  core_iv;
  wire           core_ready;
  wire [511 : 0] core_data_in;
  wire [511 : 0] core_data_out;
  wire           core_data_out_valid;

  reg [31 : 0]   tmp_read_data;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign core_init    = init_reg;

  assign core_next    = next_reg;

  assign core_keylen  = keylen_reg;

  assign core_rounds  = rounds_reg;

  assign core_key     = {key0_reg, key1_reg, key2_reg, key3_reg,
                         key4_reg, key5_reg, key6_reg, key7_reg};

  assign core_iv      = {iv0_reg, iv1_reg};

  assign core_data_in = {data_in0_reg, data_in1_reg, data_in2_reg, data_in3_reg,
                         data_in4_reg, data_in5_reg, data_in6_reg, data_in7_reg,
                         data_in8_reg, data_in9_reg, data_in10_reg, data_in11_reg,
                         data_in12_reg, data_in13_reg, data_in14_reg, data_in15_reg};

  assign read_data = tmp_read_data;


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
          init_reg           <= 0;
          next_reg           <= 0;
          ready_reg          <= 0;
          keylen_reg         <= 0;
          rounds_reg         <= 5'b00000;
          data_out_valid_reg <= 0;

          key0_reg           <= 32'h00;
          key1_reg           <= 32'h00;
          key2_reg           <= 32'h00;
          key3_reg           <= 32'h00;
          key4_reg           <= 32'h00;
          key5_reg           <= 32'h00;
          key6_reg           <= 32'h00;
          key7_reg           <= 32'h00;
          iv0_reg            <= 32'h00;
          iv1_reg            <= 32'h00;
          data_in0_reg       <= 32'h00;
          data_in1_reg       <= 32'h00;
          data_in2_reg       <= 32'h00;
          data_in3_reg       <= 32'h00;
          data_in4_reg       <= 32'h00;
          data_in5_reg       <= 32'h00;
          data_in6_reg       <= 32'h00;
          data_in7_reg       <= 32'h00;
          data_in8_reg       <= 32'h00;
          data_in9_reg       <= 32'h00;
          data_in10_reg      <= 32'h00;
          data_in11_reg      <= 32'h00;
          data_in12_reg      <= 32'h00;
          data_in13_reg      <= 32'h00;
          data_in14_reg      <= 32'h00;
          data_in15_reg      <= 32'h00;
          data_out0_reg      <= 32'h00;
          data_out1_reg      <= 32'h00;
          data_out2_reg      <= 32'h00;
          data_out3_reg      <= 32'h00;
          data_out4_reg      <= 32'h00;
          data_out5_reg      <= 32'h00;
          data_out6_reg      <= 32'h00;
          data_out7_reg      <= 32'h00;
          data_out8_reg      <= 32'h00;
          data_out9_reg      <= 32'h00;
          data_out10_reg     <= 32'h00;
          data_out11_reg     <= 32'h00;
          data_out12_reg     <= 32'h00;
          data_out13_reg     <= 32'h00;
          data_out14_reg     <= 32'h00;
          data_out15_reg     <= 32'h00;
        end
      else
        begin
          ready_reg          <= core_ready;
          data_out_valid_reg <= core_data_out_valid;

          if (ctrl_we)
            begin
              init_reg <= write_data[CTRL_INIT_BIT];
              next_reg <= write_data[CTRL_NEXT_BIT];
            end

          if (keylen_we)
            keylen_reg <= write_data[KEYLEN_BIT];

          if (rounds_we)
            rounds_reg <= write_data[ROUNDS_HIGH_BIT : ROUNDS_LOW_BIT];

          if (key0_we)
            key0_reg <= write_data;

          if (key1_we)
            key1_reg <= write_data;

          if (key2_we)
            key2_reg <= write_data;

          if (key3_we)
            key3_reg <= write_data;

          if (key4_we)
            key4_reg <= write_data;

          if (key5_we)
            key5_reg <= write_data;

          if (key6_we)
            key6_reg <= write_data;

          if (key7_we)
            key7_reg <= write_data;

          if (iv0_we)
            iv0_reg <= write_data;

          if (iv1_we)
            iv1_reg <= write_data;

          if (data_in0_we)
            data_in0_reg <= write_data;

          if (data_in1_we)
            data_in1_reg <= write_data;

          if (data_in2_we)
            data_in2_reg <= write_data;

          if (data_in3_we)
            data_in3_reg <= write_data;

          if (data_in4_we)
            data_in4_reg <= write_data;

          if (data_in5_we)
            data_in5_reg <= write_data;

          if (data_in6_we)
            data_in6_reg <= write_data;

          if (data_in7_we)
            data_in7_reg <= write_data;

          if (data_in8_we)
            data_in8_reg <= write_data;

          if (data_in9_we)
            data_in9_reg <= write_data;

          if (data_in10_we)
            data_in10_reg <= write_data;

          if (data_in11_we)
            data_in11_reg <= write_data;

          if (data_in12_we)
            data_in12_reg <= write_data;

          if (data_in13_we)
            data_in13_reg <= write_data;

          if (data_in14_we)
            data_in14_reg <= write_data;

          if (data_in15_we)
            data_in15_reg <= write_data;

          if (core_data_out_valid)
            begin
              data_out0_reg  <= core_data_out[511 : 480];
              data_out1_reg  <= core_data_out[479 : 448];
              data_out2_reg  <= core_data_out[447 : 416];
              data_out3_reg  <= core_data_out[415 : 384];
              data_out4_reg  <= core_data_out[383 : 352];
              data_out5_reg  <= core_data_out[351 : 320];
              data_out6_reg  <= core_data_out[319 : 288];
              data_out7_reg  <= core_data_out[287 : 256];
              data_out8_reg  <= core_data_out[255 : 224];
              data_out9_reg  <= core_data_out[223 : 192];
              data_out10_reg <= core_data_out[191 : 160];
              data_out11_reg <= core_data_out[159 : 128];
              data_out12_reg <= core_data_out[127 :  96];
              data_out13_reg <= core_data_out[95  :  64];
              data_out14_reg <= core_data_out[63  :  32];
              data_out15_reg <= core_data_out[31  :   0];
            end
        end
    end // reg_update


  //----------------------------------------------------------------
  // Address decoder logic.
  //----------------------------------------------------------------
  always @*
    begin : addr_decoder
      ctrl_we      = 0;
      keylen_we    = 0;
      rounds_we    = 0;
      key0_we      = 0;
      key1_we      = 0;
      key2_we      = 0;
      key3_we      = 0;
      key4_we      = 0;
      key5_we      = 0;
      key6_we      = 0;
      key7_we      = 0;
      iv0_we       = 0;
      iv1_we       = 0;
      data_in0_we  = 0;
      data_in1_we  = 0;
      data_in2_we  = 0;
      data_in3_we  = 0;
      data_in4_we  = 0;
      data_in5_we  = 0;
      data_in6_we  = 0;
      data_in7_we  = 0;
      data_in8_we  = 0;
      data_in9_we  = 0;
      data_in10_we = 0;
      data_in11_we = 0;
      data_in12_we = 0;
      data_in13_we = 0;
      data_in14_we = 0;
      data_in15_we = 0;
      tmp_read_data = 32'h00;

      if (cs)
        begin
          if (we)
            begin
              case (address)
                ADDR_CTRL:
                  ctrl_we  = 1;

                ADDR_KEYLEN:
                  keylen_we = 1;

                ADDR_ROUNDS:
                  rounds_we  = 1;

                ADDR_KEY0:
                  key0_we  = 1;

                ADDR_KEY1:
                  key1_we  = 1;

                ADDR_KEY2:
                  key2_we  = 1;

                ADDR_KEY3:
                  key3_we  = 1;

                ADDR_KEY4:
                  key4_we  = 1;

                ADDR_KEY5:
                  key5_we  = 1;

                ADDR_KEY6:
                  key6_we  = 1;

                ADDR_KEY7:
                  key7_we  = 1;

                ADDR_IV0:
                  iv0_we = 1;

                ADDR_IV1:
                  iv1_we = 1;

                ADDR_DATA_IN0:
                  data_in0_we = 1;

                ADDR_DATA_IN1:
                  data_in1_we = 1;

                ADDR_DATA_IN2:
                  data_in2_we = 1;

                ADDR_DATA_IN3:
                  data_in3_we = 1;

                ADDR_DATA_IN4:
                  data_in4_we = 1;

                ADDR_DATA_IN5:
                  data_in5_we = 1;

                ADDR_DATA_IN6:
                  data_in6_we = 1;

                ADDR_DATA_IN7:
                  data_in7_we = 1;

                ADDR_DATA_IN8:
                  data_in8_we = 1;

                ADDR_DATA_IN9:
                  data_in9_we = 1;

                ADDR_DATA_IN10:
                  data_in10_we = 1;

                ADDR_DATA_IN11:
                  data_in11_we = 1;

                ADDR_DATA_IN12:
                  data_in12_we = 1;

                ADDR_DATA_IN13:
                  data_in13_we = 1;

                ADDR_DATA_IN14:
                  data_in14_we = 1;

                ADDR_DATA_IN15:
                  data_in15_we = 1;

                default:
                  begin
                  end
              endcase // case (address)
            end // if (we)

          else
            begin
              case (address)
                ADDR_CTRL:
                  tmp_read_data = {28'h0000000, 2'b00, next_reg, init_reg};

                ADDR_STATUS:
                  tmp_read_data = {28'h0000000, 2'b00,
                                   {data_out_valid_reg, ready_reg}};

                ADDR_KEYLEN:
                  tmp_read_data = {28'h0000000, 3'b000, keylen_reg};

                ADDR_ROUNDS:
                  tmp_read_data = {24'h000000, 3'b000, rounds_reg};

                ADDR_KEY0:
                  tmp_read_data = key0_reg;

                ADDR_KEY1:
                  tmp_read_data = key1_reg;

                ADDR_KEY2:
                  tmp_read_data = key2_reg;

                ADDR_KEY3:
                  tmp_read_data = key3_reg;

                ADDR_KEY4:
                  tmp_read_data = key4_reg;

                ADDR_KEY5:
                  tmp_read_data = key5_reg;

                ADDR_KEY6:
                  tmp_read_data = key6_reg;

                ADDR_KEY7:
                  tmp_read_data = key7_reg;

                ADDR_IV0:
                  tmp_read_data = iv0_reg;

                ADDR_IV1:
                  tmp_read_data = iv1_reg;

                ADDR_DATA_OUT0:
                  tmp_read_data = data_out0_reg;

                ADDR_DATA_OUT1:
                  tmp_read_data = data_out1_reg;

                ADDR_DATA_OUT2:
                  tmp_read_data = data_out2_reg;

                ADDR_DATA_OUT3:
                  tmp_read_data = data_out3_reg;

                ADDR_DATA_OUT4:
                  tmp_read_data = data_out4_reg;

                ADDR_DATA_OUT5:
                  tmp_read_data = data_out5_reg;

                ADDR_DATA_OUT6:
                  tmp_read_data = data_out6_reg;

                ADDR_DATA_OUT7:
                  tmp_read_data = data_out7_reg;

                ADDR_DATA_OUT8:
                  tmp_read_data = data_out8_reg;

                ADDR_DATA_OUT9:
                  tmp_read_data = data_out9_reg;

                ADDR_DATA_OUT10:
                    tmp_read_data = data_out10_reg;

                ADDR_DATA_OUT11:
                  tmp_read_data = data_out11_reg;

                ADDR_DATA_OUT12:
                  tmp_read_data = data_out12_reg;

                ADDR_DATA_OUT13:
                  tmp_read_data = data_out13_reg;

                ADDR_DATA_OUT14:
                  tmp_read_data = data_out14_reg;

                ADDR_DATA_OUT15:
                  tmp_read_data = data_out15_reg;

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
