------------------------------ MODULE typedefs --------------------------------
(*
 A module defining type aliases for TFTP specification.

 Igor Konnov, 2025
 *)
EXTENDS Naturals, Sequences, Variants

\* TFTP opcodes as per RFC 1350 and RFC 2347
OPCODE_RRQ == 1
OPCODE_WRQ == 2
OPCODE_DATA == 3
OPCODE_ACK == 4
OPCODE_ERROR == 5
OPCODE_OACK == 6

(*
  // TFTP Packet Types
  @typeAlias: tftpPacket =
    // Read Request (RFC 1350, Figure 5-1, RFC 2347).
    // See RFCs 2348-2349 for the options.
      RRQ({ opcode: Int, filename: Str, mode: Str, options: Str -> Int })
    // Write Request (RFC 1350, Figure 5-1, RFC 2347).
    // See RFCs 2348-2349 for the options.
    | WRQ({ opcode: Int, filename: Str, mode: Str, options: Str -> Int })
    // Acknowledgment (RFC 1350, Figure 5-3)
    | ACK({ opcode: Int, blockNum: Int })
    // Option Acknowledgment (RFC 2347)
    | OACK({ opcode: Int, options: Str -> Int })
    // Data packet (RFC 1350, Figure 5-2)
    // In our specification, we simply pass the length of data instead of the
    // data itself. The test harness should pass the actual data.
    | DATA({ opcode: Int, blockNum: Int, data: Int })
    // Error packet (RFC 1350, Figure 5-4).
    // We omit error messages as they differ in practice and are not relevant for the spec.
    | ERROR({ opcode: Int, errorCode: Int })
  ;

  // UDP Packet encapsulating a TFTP packet (we omit irrelevant fields).
  @typeAlias: udpPacket = {
    srcIp: Str,
    srcPort: Int,
    destIp: Str,
    destPort: Int,
    payload: $tftpPacket
  };

  // Internal data structure representing an active TFTP transfer (not specified in RFCs).
  // We use the same data structure for both server and client transfers.
  @typeAlias: transfer = {
    // the server port allocated for this transfer
    port: Int,
    // the total size of the file being transferred
    tsize: Int,
    // the block size negotiated for this transfer (or 512)
    blksize: Int,
    // the timeout value negotiated for this transfer (or 255)
    timeout: Int,
    // The block number of the last block sent/received.
    blockNum: Int,
    // The timestamp of the last activity on this transfer.
    timestamp: Int,
    // Total bytes transferred so far.
    transferred: Int,
    // The blocks received so far.
    // We store the length of each block instead of the actual bytes.
    // The test harness should manage the actual bytes.
    blocks: Seq(Int)
  };

  // Action types for tracking the last action taken
  @typeAlias: action =
      ActionInit(UNIT)
    | ActionClientSendRRQ({ sent: $udpPacket })
    // only save the sent packet, as it is hard to recover the sent packet from received one
    | ActionRecvSend({ sent: $udpPacket })
    | ActionClientTimeout({ ipPort: <<Str, Int>> })
    | ActionServerTimeout({ ipPort: <<Str, Int>> })
    | ActionAdvanceClock({ delta: Int })
    | ActionRecvClose({ rcvd: $udpPacket });
 *)
typedefs_aliases == TRUE

\* Constructors and accessors for TFTP packet variants (generated with Copilot/Claude)

\* @type: (Str, Str, Str -> Int) => $tftpPacket;
RRQ(_filename, _mode, _options) ==
  Variant("RRQ",
    [opcode |-> OPCODE_RRQ, filename |-> _filename, mode |-> _mode, options |-> _options])

\* @type: $tftpPacket => Bool;
IsRRQ(_packet) == VariantTag(_packet) = "RRQ"

\* @type: $tftpPacket => { opcode: Int, filename: Str, mode: Str, options: Str -> Int };
AsRRQ(_packet) == VariantGetUnsafe("RRQ", _packet)

\* @type: (Str, Str, Str -> Int) => $tftpPacket;
WRQ(_filename, _mode, _options) ==
  Variant("WRQ",
    [opcode |-> OPCODE_WRQ, filename |-> _filename, mode |-> _mode, options |-> _options])

\* @type: $tftpPacket => Bool;
IsWRQ(_packet) == VariantTag(_packet) = "WRQ"

\* @type: $tftpPacket => { opcode: Int, filename: Str, mode: Str, options: Str -> Int };
AsWRQ(_packet) == VariantGetUnsafe("WRQ", _packet)

\* @type: Int => $tftpPacket;
ACK(_blockNum) ==
  Variant("ACK", [opcode |-> OPCODE_ACK, blockNum |-> _blockNum])

\* @type: $tftpPacket => Bool;
IsACK(_packet) == VariantTag(_packet) = "ACK"

\* @type: $tftpPacket => { opcode: Int, blockNum: Int };
AsACK(_packet) == VariantGetUnsafe("ACK", _packet)

\* @type: (Str -> Int) => $tftpPacket;
OACK(_options) ==
  Variant("OACK", [opcode |-> OPCODE_OACK, options |-> _options])

\* @type: $tftpPacket => Bool;
IsOACK(_packet) == VariantTag(_packet) = "OACK"

\* @type: $tftpPacket => { opcode: Int, options: Str -> Int };
AsOACK(_packet) == VariantGetUnsafe("OACK", _packet)

\* @type: (Int, Int) => $tftpPacket;
DATA(_blockNum, _data) ==
  Variant("DATA", [opcode |-> OPCODE_DATA, blockNum |-> _blockNum, data |-> _data])

\* @type: $tftpPacket => Bool;
IsDATA(_packet) == VariantTag(_packet) = "DATA"

\* @type: $tftpPacket => { opcode: Int, blockNum: Int, data: Int };
AsDATA(_packet) == VariantGetUnsafe("DATA", _packet)

\* @type: (Int) => $tftpPacket;
ERROR(_errorCode) ==
  Variant("ERROR", [opcode |-> OPCODE_ERROR, errorCode |-> _errorCode])

\* @type: $tftpPacket => Bool;
IsERROR(_packet) == VariantTag(_packet) = "ERROR"

\* @type: $tftpPacket => { opcode: Int, errorCode: Int };
AsERROR(_packet) == VariantGetUnsafe("ERROR", _packet)

\* Constructor for UDP packet
\* @type: (Str, Int, Str, Int, $tftpPacket) => $udpPacket;
UDPPacket(_srcIp, _srcPort, _destIp, _destPort, _payload) ==
  [srcIp |-> _srcIp, srcPort |-> _srcPort,
   destIp |-> _destIp, destPort |-> _destPort, payload |-> _payload]

\* Constructors for action variants

\* @type: () => $action;
ActionInit == Variant("ActionInit", "u_OF_UNIT")

\* @type: ($udpPacket) => $action;
ActionClientSendRRQ(_sent) == Variant("ActionClientSendRRQ", [sent |-> _sent])

\* @type: (<<Str, Int>>) => $action;
ActionClientTimeout(_ipPort) == Variant("ActionClientTimeout", [ipPort |-> _ipPort])

\* @type: (<<Str, Int>>) => $action;
ActionServerTimeout(_ipPort) == Variant("ActionServerTimeout", [ipPort |-> _ipPort])

\* @type: (Int) => $action;
ActionAdvanceClock(_delta) == Variant("ActionAdvanceClock", [delta |-> _delta])

\* @type: ($udpPacket) => $action;
ActionRecvSend(_sent) == Variant("ActionRecvSend", [sent |-> _sent])

\* @type: ($udpPacket) => $action;
ActionRecvClose(_rcvd) == Variant("ActionRecvClose", [rcvd |-> _rcvd])

===============================================================================