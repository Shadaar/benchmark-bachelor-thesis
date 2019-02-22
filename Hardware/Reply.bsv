package Reply;
import AXI4_Stream     :: *;
import AXI4_Lite_Types :: *;
import AXI4_Lite_Slave :: *;
import BlueLibNetwork  :: *;
import GetPut          :: *;
import Connectable     :: *;
import FIFOF           :: *;
import SpecialFIFOs    :: *;


(* always_ready, always_enabled *)
interface AXI4_Lite;
  (* prefix = "" *)interface AXI4_Lite_Slave_Rd_Fab#(12,32) read;
  (* prefix = "" *)interface AXI4_Lite_Slave_Wr_Fab#(12,32) write;
endinterface

interface Passthrough;
  interface AXI4_Stream_Wr_Fab#(64,1) axis_M;
  interface AXI4_Stream_Rd_Fab#(64,1) axis_S;
  interface AXI4_Lite                 axi4_S;
endinterface

module mkReply(Passthrough);
  AXI4_Stream_Wr#(64, 1) streamOut   <- mkAXI4_Stream_Wr(1);
  AXI4_Stream_Rd#(64, 1)  streamIn   <- mkAXI4_Stream_Rd(1);
  AXI4_Lite_Slave_Wr#(12,32) axiw    <- mkAXI4_Lite_Slave_Wr(1);
  AXI4_Lite_Slave_Rd#(12,32) axir    <- mkAXI4_Lite_Slave_Rd(1);
  
  Reg#(UInt#(32))        counter    <- mkReg(0);
  Reg#(UInt#(32))        reading    <- mkReg(0);
  Reg#(Bool)             done       <- mkReg(False);
  
  Reg#(Bit#(64))         debug_first   <- mkReg(0);
  Reg#(Bit#(64))         debug_second  <- mkReg(0);
  Reg#(Bit#(64))         debug_third   <- mkReg(0);
  Reg#(Bit#(64))         debug_four    <- mkReg(0);

  
    AXI4_Stream_Pkg#(64, 1) dummy;
  dummy.data = toggleEndianess('h3031323334353637);
  dummy.keep = 'hff;
  dummy.user = 0;
  dummy.dest = 0;
  dummy.last = False;
  
  Reg#(AXI4_Stream_Pkg#(64, 1))         buffer   <- mkReg(dummy);
  FIFOF#(AXI4_Stream_Pkg#(64, 1))       next     <- mkSizedBypassFIFOF(1200);
  

  // ------------------------------------------------------------------  
    rule axi_stream_read0(reading == 0 && next.notFull);
        AXI4_Stream_Pkg#(64, 1) stream <- streamIn.pkg.get();
        buffer <= stream;
        debug_first <= stream.data;
        
        reading <=  1;
    endrule
    
    rule axi_stream_read1(reading == 1 && !done);
        AXI4_Stream_Pkg#(64, 1) stream <- streamIn.pkg.get();

        Bit#(48) dest   = {stream.data[31:0], buffer.data[63:48]};
        Bit#(48) source = buffer.data[47:0];
        
        AXI4_Stream_Pkg#(64, 1) first  = buffer;
        first.data = {source[15:0], dest}; 
        stream.data = {stream.data[63:32], source[47:16]};    

        debug_second <= stream.data;
        debug_third[47:0] <= dest;
        debug_four[47:0] <= source;
        
        next.enq(first);
        buffer <= stream;
    
        reading <= 2;
    endrule

     rule axi_stream_read2(reading == 2 && !done);
        AXI4_Stream_Pkg#(64, 1) stream <- streamIn.pkg.get();
        buffer <= stream;
        next.enq(buffer);
        
        if (stream.last) reading <= 0;
        if (stream.last) done <= True;
    endrule
    
    rule axi_stream_read3(done);
        next.enq(buffer);
        counter <= counter + 1;
        done <= False; 
    endrule
 // ------------------------------------------------------------------   
    rule axis_send1;
        AXI4_Stream_Pkg#(64, 1) stream = next.first;
        stream.user = 0;
        stream.dest = 0;
        
        streamOut.pkg.put(stream);
        next.deq();
    endrule
 // ------------------------------------------------------------------    
    rule axi_read;
        AXI4_Lite_Read_Rq_Pkg#(12)  axrq <- axir.request.get();
        AXI4_Lite_Read_Rs_Pkg#(32) axrs;
        axrs.data = case(axrq.addr)
             0: pack(debug_first[31:0]);
             4: pack(debug_first[63:32]);
             8: pack(debug_second[31:0]);
            12: pack(debug_second[63:32]);
            16: pack(debug_third[31:0]);
            20: pack(debug_third[63:32]);
            24: pack(debug_four[31:0]);
            28: pack(debug_four[63:32]);
            32: pack(counter);
        endcase;   
        axrs.resp = OKAY;
        axir.response.put(axrs);
    endrule

    rule axi_write;
        AXI4_Lite_Write_Rq_Pkg#(12,32) axwrq <- axiw.request.get();
        AXI4_Lite_Write_Rs_Pkg axwrs;
        axwrs.resp = OKAY;
        axiw.response.put(axwrs);
    endrule
    
 // ------------------------------------------------------------------   
    interface AXI4_Lite axi4_S;
        interface AXI4_Lite_Slave_Rd_Fab read   = axir.fab;
        interface AXI4_Lite_Slave_Wr_Fab write  = axiw.fab;
    endinterface
    
    interface AXI4_Stream_Rd_Fab     axis_S = streamIn.fab;
    interface AXI4_Stream_Wr_Fab     axis_M = streamOut.fab;
  endmodule
endpackage
