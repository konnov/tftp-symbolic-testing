------------------------------- MODULE MC2_tftp --------------------------------
(*
 An instance of the TFTP specification module for model checking with Apalache.

 Igor Konnov, 2025
 *)
EXTENDS Integers, Apalache

SERVER_IP == "10.0.0.1"
CLIENT_IPS == {"10.0.0.2", "10.0.0.3"}
PORTS == 1024..1027
FILES == SetAsFun({
    <<"file1", 1024>>,
    <<"file2", 2099>>,
    <<"file3", 12345>>
})

VARIABLES
    \* The set of UDP packets in the system.
    \* @type: Set($udpPacket);
    packets,
    \* TFTP serverConnections as handled by the server.
    \* Mapping from (client IP, client port) to server port.
    \* @type: <<Str, Int>> -> $transfer;
    serverTransfers,
    \* TFTP client transfers as handled by a client.
    \* Mapping from (client IP, client port) to the transfer data structure.
    \* @type: <<Str, Int>> -> $transfer;
    clientTransfers,
    \* A global clock to model timeouts (not specified in the RFCs).
    \* We assume that the clocks are synchronized.
    \* @type: Int;
    clock

INSTANCE tftp

\* @type: << <<Str, Int>> -> $transfer, <<Str, Int>> -> $transfer >>;
View == << serverTransfers, clientTransfers>>

(* Abstract transfer records to small equivalence classes.
   @typeAlias: absTransfer = {
    port: Int,
    tsize: Int,
    blksize: Int,
    timeout: Int,
    blockNum: Int,
    timestamp: Int
  };
  @type: $transfer => $absTransfer;
 *)
AbsTransfer(t) ==
    [ port |-> t.port,
      \* -1, 0, [1, ...)
      tsize |-> Min(t.tsize, 1),
      \* abstract [0, 512), [512, 1024), [1024, 1536), ...
      blksize |-> t.blksize \div 512,
      \* interval abstraction [0, 10], [11, 255]
      timeout |-> IF t.timeout <= 10 THEN 10 ELSE 255,
      \* keep exact blockNum
      blockNum |-> t.blockNum,
      \* simply whether we are below or above the timeout threshold
      timestamp |-> IF clock <= t.timestamp + t.timeout THEN -1 ELSE 1
    ]

\* Compute the measure as the max of block numbers of all transfers.
\* @type: (<<Str, Int>> -> $transfer) => Int;
Measure(t) ==
    LET MaxS(S) == ApaFoldSet(LAMBDA x, y: Max(x, y), 0, S) IN
    MaxS({ t[ipPort].blockNum : ipPort \in DOMAIN t })

\* Use the number of transferred blocks as the measure for computing
\* the fitness function. The rest of the view is used for filtering
\* similar states.
\* @type: << Int, <<Str, Int>> -> $absTransfer, <<Str, Int>> -> $absTransfer >>;
MeasureView == <<
    (1 + Measure(serverTransfers) + Measure(clientTransfers)) * 10,
    [ p \in DOMAIN serverTransfers |-> AbsTransfer(serverTransfers[p]) ],
    [ p \in DOMAIN clientTransfers |-> AbsTransfer(clientTransfers[p]) ]
>>

\* Use the number of transferred blocks as the measure for computing
\* the fitness function. The rest of the view is used for filtering
\* similar states.
\* @type: << Int >>;
OnlyMeasureView == <<
    (1 + Measure(serverTransfers) + Measure(clientTransfers)) * 10
>>

\* Count the image cardinalities (Parikh image) combined with a map.
\* @type: (a -> b) => (b -> Int);
CountImg(f) ==
    LET V == { f[id]: id \in DOMAIN f } IN
    [ v \in V |-> Cardinality({ id \in DOMAIN f: f[id] = v }) ]

\* Use the number of transferred blocks as the measure for computing
\* the fitness function. The rest of the view is used for filtering
\* similar states.
\* @type: << Int, Int, Int, (Int -> Int), (Int -> Int) >>;
MeasureAndPacketsView == <<
    (1 + Measure(serverTransfers) + Measure(clientTransfers)) * 10,
    \* restrict the number of the RRQ and ERROR packets to reduce noise
    Min(Cardinality({ p \in packets: IsRRQ(p.payload) }), 4),
    Min(Cardinality({ p \in packets: IsERROR(p.payload) }), 5),
    \* only keep the block numbers
    CountImg([ p \in DOMAIN serverTransfers |-> serverTransfers[p].blockNum ]),
    CountImg([ p \in DOMAIN clientTransfers |-> clientTransfers[p].blockNum ])
>>

\* Count the image cardinalities (Parikh image) combined with a map.
\* @type: (a -> b, (Int => Int)) => (b -> Int);
CountImgAndMap(f, map(_)) ==
    LET V == {f[id]: id \in DOMAIN f} IN
    [ v \in V |-> map(Cardinality({ id \in DOMAIN f: f[id] = v }))]

\* @type: << <<Str, Int>> -> $absTransfer, <<Str, Int>> -> $absTransfer >>;
AbsView == <<
    [ p \in DOMAIN serverTransfers |-> AbsTransfer(serverTransfers[p]) ],
    [ p \in DOMAIN clientTransfers |-> AbsTransfer(clientTransfers[p]) ]
>>

TrueInv == TRUE

(************************ Execution examples ***************************)

\* Check this falsy invariant to see an example of having 2 UDP packets.
TwoUdpPacketsEx ==
    ~(Cardinality(packets) >= 2)

OneDataPacketEx ==
    ~(\E p \in packets: IsDATA(p.payload))

\* Check this falsy invariant to see an example of a client receiving 2 blocks.
RecvOneDataBlockEx ==
    ~(\E p \in DOMAIN clientTransfers:
        Len(clientTransfers[p].blocks) >= 1)

\* Check this falsy invariant to see an example of a client receiving 2 blocks.
RecvTwoDataBlocksEx ==
    ~(\E p \in DOMAIN clientTransfers:
        Len(clientTransfers[p].blocks) >= 2)

\* Check this falsy invariant to see an example of a client receiving 3 blocks.
RecvThreeDataBlocksEx ==
    ~(\E p \in DOMAIN clientTransfers:
        Len(clientTransfers[p].blocks) >= 3)

\* Check this falsy invariant to see an example of a client receiving 5 blocks.
RecvFiveDataBlocksEx ==
    ~(\E p \in DOMAIN clientTransfers:
        Len(clientTransfers[p].blocks) >= 5)

\* Check this falsy invariant to see an example of the server having a transfer
\* entry.
ServerTransfersEx ==
    ~(DOMAIN serverTransfers /= {})


================================================================================
