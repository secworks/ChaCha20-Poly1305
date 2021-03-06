//======================================================================
//
// tb_chacha20_core.v
// ------------------
// Testbench for the Chacha stream cipher core. This TB verifies that
// the chacha20 core can be used as specified in RFC 7539. The
// big change is that the original core has 64 bit IV and 64 bit
// counter. In RFC 7539, the IV (called nonce in the RFC) is 96 bits
// and the counter is 32 bits. Also, in the RFC, the key is always
// 256 bits and uses 20 rounds.  Testvectors are taken from the RFC.
//
//
// Copyright (c) 2016, Assured AB
// All rights reserved.
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

module tb_chacha20_core();

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter CLK_HALF_PERIOD = 1;
  parameter CLK_PERIOD      = 2 * CLK_HALF_PERIOD;
  parameter KEY_256_BITS    = 1;
  parameter TWENTY_ROUNDS   = 20;


  //----------------------------------------------------------------
  // l2b()
  //
  // Swap bytes from little to big endian byte order.
  //----------------------------------------------------------------
  function [31 : 0] l2b(input [31 : 0] op);
    begin
      l2b = {op[7 : 0], op[15 : 8], op[23 : 16], op[31 : 24]};
    end
  endfunction // b2l


  //----------------------------------------------------------------
  // Register and Wire declarations.
  //----------------------------------------------------------------
  reg [31 : 0] cycle_ctr;
  reg [31 : 0] error_ctr;
  reg [31 : 0] tc_ctr;

  reg tb_clk;
  reg tb_reset_n;

  reg            tb_core_init;
  reg            tb_core_next;
  reg [255 : 0]  tb_core_key;
  reg            tb_core_keylen;
  reg [4 : 0]    tb_core_rounds;
  reg [95 : 0]   tb_core_nonce;
  reg [31 : 0]   tb_core_ctr;
  wire           tb_core_ready;
  reg [0 : 511]  tb_core_data_in;
  wire [0 : 511] tb_core_data_out;

  reg            display_cycle_ctr;
  reg            display_ctrl_and_ctrs;
  reg            display_qround;
  reg            display_state;
  reg            display_x_state;


  //----------------------------------------------------------------
  // chacha_core device under test.
  //
  // Note that we instantiate with a l2b fix for the msb
  // part of the counter.
  //----------------------------------------------------------------
  chacha_core dut(
                  .clk(tb_clk),
                  .reset_n(tb_reset_n),
                  .init(tb_core_init),
                  .next(tb_core_next),
                  .key(tb_core_key),
                  .keylen(tb_core_keylen),
                  .iv(tb_core_nonce[63 : 0]),
                  .ctr({l2b(tb_core_nonce[95 : 64]), tb_core_ctr}),
                  .rounds(tb_core_rounds),
                  .data_in(tb_core_data_in),
                  .ready(tb_core_ready),
                  .data_out(tb_core_data_out),
                  .data_out_valid(tb_core_data_out_valid)
                 );


  //----------------------------------------------------------------
  // clk_gen
  //
  // Clock generator process.
  //----------------------------------------------------------------
  always
    begin : clk_gen
      #CLK_HALF_PERIOD tb_clk = !tb_clk;
    end // clk_gen


  //--------------------------------------------------------------------
  // dut_monitor
  //
  // Monitor that displays different types of information
  // every cycle depending on what flags test cases enable.
  //
  // The monitor includes a cycle counter for the testbench.
  //--------------------------------------------------------------------
  always @ (posedge tb_clk)
    begin : dut_monitor
      cycle_ctr = cycle_ctr + 1;

      dump_state();

      // Display cycle counter.
      if (display_cycle_ctr)
        begin
          $display("cycle = %08x:", cycle_ctr);
          $display("");
        end
    end // dut_monitor


  //----------------------------------------------------------------
  // dump_state()
  // Dump the internal CHACHA state to std out.
  //----------------------------------------------------------------
  task dump_state;
    begin
      $display("");
      $display("Internal state:");
      $display("---------------");
      $display("State:");
      $display("state00_reg = %08x state01_reg = %08x state02_reg = %08x state03_reg = %08x",
               dut.state_reg[00], dut.state_reg[01], dut.state_reg[02], dut.state_reg[03]);
      $display("state04_reg = %08x state05_reg = %08x state06_reg = %08x state07_reg = %08x",
               dut.state_reg[04], dut.state_reg[05], dut.state_reg[06], dut.state_reg[07]);
      $display("state08_reg = %08x state09_reg = %08x state10_reg = %08x state11_reg = %08x",
               dut.state_reg[08], dut.state_reg[09], dut.state_reg[10], dut.state_reg[11]);
      $display("state12_reg = %08x state13_reg = %08x state14_reg = %08x state15_reg = %08x",
               dut.state_reg[12], dut.state_reg[13], dut.state_reg[14], dut.state_reg[15]);
      $display("");

      $display("rounds = %01x", dut.rounds);
      $display("qr_ctr_reg = %01x, dr_ctr_reg  = %01x", dut.qr_ctr_reg, dut.dr_ctr_reg);
      $display("block0_ctr_reg = %08x, block1_ctr_reg = %08x", dut.block0_ctr_reg, dut.block1_ctr_reg);
      $display("");

      $display("chacha_ctrl_reg = %02x", dut.chacha_ctrl_reg);
      $display("");

      $display("data_in[255 : 192] = %016x", dut.data_in[255 : 192]);
      $display("data_in[191 : 128] = %016x", dut.data_in[191 : 128]);
      $display("data_in[127 : 064] = %016x", dut.data_in[127 : 064]);
      $display("data_in[063 : 000] = %016x", dut.data_in[063 : 000]);
      $display("data_out_valid_reg = %01x", dut.data_out_valid_reg);
      $display("data_out           = %064x", dut.data_out);
      $display("");
    end
  endtask // dump_state


  //----------------------------------------------------------------
  // dump_inout()
  // Dump the status for input and output ports.
  //----------------------------------------------------------------
  task dump_inout;
    begin
      $display("");
      $display("State for input and output ports:");
      $display("---------------------------------");
      $display("init       = %01x", dut.init);
      $display("next       = %01x", dut.next);
      $display("keylen     = %01x", dut.keylen);
      $display("");

      $display("key = %032x", dut.key);
      $display("iv  = %016x", dut.iv);
      $display("");

      $display("ready          = %01x", dut.ready);
      $display("data_in        = %064x", dut.data_in);
      $display("data_out       = %064x", dut.data_out);
      $display("data_out_valid = %01x", dut.data_out_valid);
      $display("");
    end
  endtask // dump_inout


  //----------------------------------------------------------------
  // display_test_result()
  //
  // Display the accumulated test results.
  //----------------------------------------------------------------
  task display_test_result;
    begin
      if (error_ctr == 0)
        begin
          $display("*** All %d test cases completed successfully", tc_ctr);
        end
      else
        begin
          $display("*** %02d test cases did not complete successfully.", error_ctr);
        end
    end
  endtask // display_test_result


  //----------------------------------------------------------------
  // reset_dut()
  //
  // Toggle reset to put the DUT into a well known state.
  //----------------------------------------------------------------
  task reset_dut;
    begin
      $display("*** Toggle reset.");
      tb_reset_n = 0;
      #(4 * CLK_HALF_PERIOD);
      tb_reset_n = 1;
    end
  endtask // reset_dut


  //----------------------------------------------------------------
  // init_dut()
  //
  // Set the input to the DUT to defined values.
  //----------------------------------------------------------------
  task init_dut;
    begin
      cycle_ctr       = 0;
      error_ctr       = 0;
      tc_ctr          = 0;
      tb_clk          = 0;
      tb_reset_n      = 0;
      error_ctr       = 0;
      tb_core_init    = 0;
      tb_core_next    = 0;
      tb_core_key     = 0;
      tb_core_keylen  = 0;
      tb_core_nonce   = 96'h0;
      tb_core_ctr     = 32'h0;
      tb_core_rounds  = 0;
      tb_core_data_in = 512'h0;
    end
  endtask // init_dut


  //----------------------------------------------------------------
  // wait_ready
  //----------------------------------------------------------------
  task wait_ready;
    begin
      while (!tb_core_ready)
        begin
          #(1 * CLK_PERIOD);
        end
      $display("*** Ready seen.");
    end
  endtask // wait_ready


  //----------------------------------------------------------------
  // block_test
  //
  // Test that the initialization and block processing in the
  // chacha core conforms to the specification in RFC 7539,
  // chapter 2.3.2.
  //----------------------------------------------------------------
  task block_test;
    begin : btest
      reg test_error;
      test_error = 0;

      tc_ctr = tc_ctr + 1;

      $display("*** Block Function Test (RFC 7539, ch 2.3.2:");
      tb_core_rounds = TWENTY_ROUNDS;
      tb_core_key    = 256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
      tb_core_keylen = KEY_256_BITS;
      tb_core_nonce  = 96'h000000090000004a00000000;
      tb_core_ctr    = 32'h00000001;

      $display("*** Starting init of the cipher.");
      tb_core_init   = 1;
      #(CLK_PERIOD);
      tb_core_init   = 0;
      #(CLK_PERIOD);
      dump_state();
      dump_inout();

      // Check if state is initialized correctly.
      if (dut.state_reg[00] != 32'h61707865)
        test_error = 1;
      if (dut.state_reg[01] != 32'h3320646e)
        test_error = 1;
      if (dut.state_reg[02] != 32'h79622d32)
        test_error = 1;
      if (dut.state_reg[03] != 32'h6b206574)
        test_error = 1;
      if (dut.state_reg[04] != 32'h03020100)
        test_error = 1;
      if (dut.state_reg[05] != 32'h07060504)
        test_error = 1;
      if (dut.state_reg[06] != 32'h0b0a0908)
        test_error = 1;
      if (dut.state_reg[07] != 32'h0f0e0d0c)
        test_error = 1;
      if (dut.state_reg[08] != 32'h13121110)
        test_error = 1;
      if (dut.state_reg[09] != 32'h17161514)
        test_error = 1;
      if (dut.state_reg[10] != 32'h1b1a1918)
        test_error = 1;
      if (dut.state_reg[11] != 32'h1f1e1d1c)
        test_error = 1;
      if (dut.state_reg[12] != 32'h00000001)
        test_error = 1;
      if (dut.state_reg[13] != 32'h09000000)
        test_error = 1;
      if (dut.state_reg[14] != 32'h4a000000)
        test_error = 1;
      if (dut.state_reg[15] != 32'h00000000)
        test_error = 1;

      if (test_error)
        $display("*** State after init is not correct.");
      else
        $display("*** State after init correct.");

      $display("*** Waiting for end of processing first block.");
      wait_ready();
      dump_state();
    end
  endtask // block_test


  //----------------------------------------------------------------
  // chacha20_core_test
  //----------------------------------------------------------------
  initial
    begin : chacha20_core_test
      $display("   -- Testbench for chacha20 core started --");
      $display("");

      init_dut();
      $display("*** State at init:");
      dump_state();

      reset_dut();
      $display("*** State after reset:");
      dump_state();

      block_test();

      $display("*** chacha_core simulation done ***");
      display_test_result();
      $finish;
    end // chacha20_core_test

endmodule // tb_chacha20_core

//======================================================================
// EOF tb_chacha20_core.v
//======================================================================
