---------------------------------- MODULE tftp --------------------------------
(*
 A TLA+ specification of the Trivial File Transfer Protocol (TFTP).
 We maintain the specification close to the RFCs 1350, 2347-2349.
 The timeouts are prescribed in RFCs 1123 and 2349.

 Igor Konnov, 2025
 *)
EXTENDS Naturals, Sequences, FiniteSets, Apalache, util, typedefs

CONSTANTS
    \* The IP address of the TFTP server.
    \* @type: Str;
    SERVER_IP,
    \* The IP addresses of the TFTP clients.
    \* @type: Set(Str);
    CLIENT_IPS,
    \* The ports that are used by the server and the clients (subset of 1024..65535).
    \* @type: Set(Int);
    PORTS,
    \* The filenames that can be read/written, mapped to their sizes in bytes.
    \* @type: Str -> Int;
    FILES

VARIABLES
    \* The set of UDP packets in the system.
    \* @type: Set($udpPacket);
    packets,
    \* TFTP transfers as handled by the server (not specified in the RFCs).
    \* Mapping from (client IP, client port) to the transfer data structure.
    \* @type: <<Str, Int>> -> $transfer;
    serverTransfers,
    \* TFTP client transfers as handled by a client (not specified in the RFCs).
    \* Mapping from (client IP, client port) to the transfer data structure.
    \* @type: <<Str, Int>> -> $transfer;
    clientTransfers,
    \* A global clock to model timeouts (not specified in the RFCs).
    \* We assume that the clocks are synchronized.
    \* @type: Int;
    clock,
    \* The last action taken in the system.
    \* @type: $action;
    lastAction

\* The set of TFTP options introduced in RFCs 2348-2349
OPTIONS_RFC2349 == {"blksize", "tsize", "timeout"}

\* Error codes as per RFC 1350 and RFC 2347.
\* We do not use the actual error messages in the spec,
\* as the implementations produce various messages.
ALL_ERRORS ==
    SetAsFun({
        <<0, "Not defined">>,
        <<1, "File not found">>,
        <<2, "Access violation">>,
        <<3, "Disk full or allocation exceeded">>,
        <<4, "Illegal TFTP operation">>,
        <<5, "Unknown transfer ID">>,
        <<6, "File already exists">>,
        <<7, "No such user">>,
        <<8, "Option negotiation failed">>
    })

\* The initial state of the TFTP system.
Init ==
    Init::
    /\ packets = {}
    /\ serverTransfers = [ ipPort \in {} \X {} |-> [
                port |-> 0, blksize |-> 0, tsize |-> 0,
                timeout |-> 0, blocks |-> <<>>, blockNum |-> 0,
                timestamp |-> 0, transferred |-> 0
            ]
        ]
    /\ clientTransfers = [ ipPort \in {} \X {} |-> [
                port |-> 0, blksize |-> 0, tsize |-> 0,
                timeout |-> 0, blocks |-> <<>>, blockNum |-> 0,
                timestamp |-> 0, transferred |-> 0
            ]
        ]
    \* the clock value is not essential here, it could be arbitrary
    /\ clock = 0
    /\ lastAction = ActionInit

(********************* Send and Receive RRQ **************************)

\* A client sends a read request to the server.
\* @type: (Str, Int, Str, Str -> Int) => Bool;
ClientSendRRQ(_srcIp, _srcPort, _filename, _options) ==
    \* We only specify the "octet" mode:
    \* "mail" mode is obsolete as per RFC 1350, what is "netascii"?
    ClientSendRRQ::
    LET rrq == RRQ(_filename, "octet", _options)
        udp == [srcIp |-> _srcIp,
                srcPort |-> _srcPort,
                destIp |-> SERVER_IP,
                destPort |-> 69, \* the port is fixed as per RFC 1350
                payload |-> rrq]
    IN
    /\ <<_srcIp, _srcPort>> \notin DOMAIN clientTransfers
    /\ clientTransfers' = [
            p \in DOMAIN clientTransfers \union {<<_srcIp, _srcPort>>} |->
            IF p = <<_srcIp, _srcPort>>
            THEN [ port |-> 69, \* initial port before negotiation
                   blksize |-> IF "blksize" \in DOMAIN _options
                               THEN _options["blksize"]
                               ELSE 512,
                   tsize |-> 0,
                   timeout |-> IF "timeout" \in DOMAIN _options
                               THEN _options["timeout"]
                               ELSE 0,
                   blocks |-> <<>>,
                   blockNum |-> 0,
                   timestamp |-> clock,
                   transferred |-> 0
                ]
            ELSE clientTransfers[p]
        ]
    /\ packets' = packets \cup {udp}
    /\ lastAction' = ActionClientSendRRQ(udp)
    /\ UNCHANGED <<serverTransfers, clock>>

\* Utility action: Send DATA in response to RRQ, as per RFC 1350 and RFC 2347.
\* See ServerRecvRRQ below.
\* @type: ({ opcode: Int, filename: Str, mode: Str, options: Str -> Int },
\*           <<Str, Int>>, Int, $udpPacket) => Bool;
_ServerSendDataOnRrq(_rrq, _clientIpAndPort, _newServerPort, _rcvdPacket) ==
    ServerRecvRRQthenSendData::
    \E timeout \in 1..255:
        LET dataSize == Min(512, FILES[_rrq.filename])
            dataPacket == [
                srcIp |-> SERVER_IP, srcPort |-> _newServerPort,
                destIp |-> _clientIpAndPort[1], destPort |-> _clientIpAndPort[2],
                \* RFC 1350, Section 5-2: The first DATA packet has block number 1.
                \* We send the length of the first block of 512 octects (or less).
                payload |-> DATA(1, Min(512, FILES[_rrq.filename]))
            ]
            newTransfer == [
                port |-> _newServerPort,
                blksize |-> 512,
                tsize |-> FILES[_rrq.filename],
                timeout |-> timeout,
                blocks |-> <<>>,
                blockNum |-> 1,
                timestamp |-> clock,
                transferred |-> dataSize
            ]
        IN
        /\  packets' = packets \union { dataPacket }
        /\  serverTransfers' = [
                p \in DOMAIN serverTransfers \union {_clientIpAndPort} |->
                IF p = _clientIpAndPort
                THEN newTransfer
                ELSE serverTransfers[p]
            ]
        /\ lastAction' = ActionRecvSend(dataPacket)
        /\ UNCHANGED <<clientTransfers, clock>>

\* Utility action: Send OACK in response to RRQ, as per RFC 2347.
\* See ServerRecvRRQ below.
\* @type: ({ opcode: Int, filename: Str, mode: Str, options: Str -> Int },
\*           <<Str, Int>>, Int, $udpPacket) => Bool;
_ServerSendOackOnRrq(_rrq, _clientIpAndPort, _newServerPort, _rcvdPacket) ==
    ServerRecvRRQthenSendOack::
    \E optionsSubset \in SUBSET DOMAIN _rrq.options,
            blksize \in 0..65464, timeout \in 1..255:
        \* RFC 2349, Section 3.1: "If the server is willing to accept
        \* the blocksize option, it sends an Option Acknowledgment
        \* (OACK) to the client.  The specified value must be less
        \* than or equal to the value specified by the client."
        /\ "blksize" \notin DOMAIN _rrq.options \/ blksize <= _rrq.options["blksize"]
        \* If the server is willing to accept the timeout option, it sends an
        \* Option Acknowledgment (OACK) to the client.  The specified timeout
        \* value must match the value specified by the client.
        /\ "timeout" \notin DOMAIN _rrq.options \/ timeout = _rrq.options["timeout"]
        \* In Read Request packets, a size of "0" is specified in the request
        \* and the size of the file, in octets, is returned in the OACK.
        /\ "tsize" \notin DOMAIN _rrq.options \/ _rrq.options["tsize"] = 0
        /\  LET tsize ==
                    IF "tsize" \in DOMAIN _rrq.options THEN FILES[_rrq.filename] ELSE 0
                oackOptions == mk_options(optionsSubset, blksize, tsize, timeout)
                oackPacket == [
                    srcIp |-> SERVER_IP, srcPort |-> _newServerPort,
                    destIp |-> _clientIpAndPort[1], destPort |-> _clientIpAndPort[2],
                    payload |-> OACK(oackOptions)
                ]
            IN
            /\ packets' = packets \union {oackPacket}
            /\ lastAction' = ActionRecvSend(oackPacket)
        /\  serverTransfers' = [
                p \in DOMAIN serverTransfers \union {_clientIpAndPort} |->
                IF p = _clientIpAndPort
                THEN [ port |-> _newServerPort, blksize |-> blksize,
                       tsize |-> FILES[_rrq.filename], timeout |-> timeout,
                       blocks |-> <<>>, blockNum |-> 0, timestamp |-> clock,
                       transferred |-> 0
                    ]
                ELSE serverTransfers[p]
            ]
        /\ UNCHANGED <<clientTransfers, clock>>

\* Utility action: Send ERROR in response to RRQ, as per RFC 1350 and RFC 2347.
\* At this point, we assume that the server can simply error when it wants to.
\* See ServerRecvRRQ below.
\* @type: ({ opcode: Int, filename: Str, mode: Str, options: Str -> Int },
\*           <<Str, Int>>, Int, $udpPacket) => Bool;
_ServerSendErrorOnRrq(_rrq, _clientIpAndPort, _newServerPort, _rcvdPacket) ==
    \* FIX #1: the error is sent from a new port, not from 69!
    \* Found by the test harness.
    ServerRecvRRQthenSendError::
    \E errorCode \in DOMAIN ALL_ERRORS:
        LET errorPacket == [
                srcIp |-> SERVER_IP, srcPort |-> _newServerPort,
                destIp |-> _clientIpAndPort[1], destPort |-> _clientIpAndPort[2],
                payload |-> ERROR(errorCode)
            ]
        IN
        /\  packets' = packets \union {errorPacket}
        /\ lastAction' = ActionRecvSend(errorPacket)
        \* do not introduce a new transfer entry on error
        /\  UNCHANGED <<serverTransfers, clientTransfers, clock>>

\* The server receives RRQ and sends one of: DATA, OACK, or ERROR.
\* @type: $udpPacket => Bool;
ServerRecvRRQ(_udp) ==
    /\ IsRRQ(_udp.payload)
    /\ _udp.destIp = SERVER_IP
    /\ _udp.destPort = 69
    /\  LET rrq == AsRRQ(_udp.payload)
            clientIpAndPort == <<_udp.srcIp, _udp.srcPort>> IN
        \* The transfer has not been initiated yet.
        \* Yet, a client can open multiple connections from different ports.
        /\ clientIpAndPort \notin DOMAIN serverTransfers
        \* the server allocates a new port for the connection, if it can find one
        /\ \E newServerPort \in PORTS:
            /\ \A p \in DOMAIN serverTransfers:
                serverTransfers[p].port /= newServerPort
            \* According to RFC 2347, the server may respond with DATA or OACK
            /\  \/ _ServerSendDataOnRrq(rrq, clientIpAndPort, newServerPort, _udp)
                \/ _ServerSendOackOnRrq(rrq, clientIpAndPort, newServerPort, _udp)
                \/ _ServerSendErrorOnRrq(rrq, clientIpAndPort, newServerPort, _udp)

(************************* Receive OACK *******************************)

\* A client receives the OACK packet from the server (RRQ transfer).
\* It either accepts the options and sends ACK for block 0,
\* or rejects the options and sends ERROR.
\* @type: $udpPacket => Bool;
ClientRecvOACK(_udp) ==
    LET ipPort == <<_udp.destIp, _udp.destPort>> IN
    /\  IsOACK(_udp.payload)
    /\  _udp.srcIp = SERVER_IP
    /\  ipPort \in DOMAIN clientTransfers
    /\  LET oack == AsOACK(_udp.payload)
            transfer == clientTransfers[ipPort]
            \* Update the transfer state on the client side,
            \* unless it sends an ERROR
            newTransfer ==
                [ transfer EXCEPT
                    !.port = _udp.srcPort,
                    \* use the negotiated options, or defaults
                    !.tsize = get_or_else(oack.options, "tsize", -1),
                    !.blksize = get_or_else(oack.options, "blksize", 512),
                    !.timeout = get_or_else(oack.options, "timeout", 255),
                    !.timestamp = clock
                ]
            \* the ACK packet to send over UDP
            ackPacket == [
                srcIp |-> _udp.destIp,
                srcPort |-> _udp.destPort,
                destIp |-> _udp.srcIp,
                destPort |-> _udp.srcPort,
                payload |-> ACK(0)
            ]
        IN
        \* do not receive packets if the connection must timeout
        /\  clock <= transfer.timestamp + transfer.timeout
        \* the OACK packet is received right after RRQ (RFC 2347)
        /\  transfer.blockNum = 0
        /\  \/  ClientRecvOACKthenSendAck::
                \* the nominal case: accept OACK and send ACK for block 0
                \* However, check that the server behaves as per RFC 2347.
                /\  ("tsize" \in DOMAIN oack.options)
                        => (oack.options["tsize"] <= transfer.tsize)
                /\  ("blksize" \in DOMAIN oack.options)
                        => (oack.options["blksize"] <= transfer.blksize)
                /\  ("timeout" \in DOMAIN oack.options)
                        => (oack.options["timeout"] <= transfer.timeout)
                \* update the transfer table and send the ACK for the received DATA
                /\  clientTransfers' =
                        [ clientTransfers EXCEPT ![ipPort] = newTransfer ]
                /\  packets' = packets \union { ackPacket }
                /\ lastAction' = ActionRecvSend(ackPacket)
            \/  ClientRecvOACKthenSendError::
                \* the client may also reject the OACK by sending an ERROR
                LET errorPacket == [
                    srcIp |-> _udp.destIp,
                    srcPort |-> _udp.destPort,
                    destIp |-> _udp.srcIp,
                    destPort |-> _udp.srcPort,
                    payload |-> ERROR(8)
                ] IN
                \* send the ERROR packet and close the connection
                /\  packets' = packets \union { errorPacket }
                /\  clientTransfers' = [
                        p \in DOMAIN clientTransfers \ { ipPort } |->
                            clientTransfers[p]
                    ]
                /\ lastAction' = ActionRecvSend(errorPacket)
    /\ UNCHANGED <<serverTransfers, clock>>

(********************* Send and Receive DATA **************************)

\* A client receives a DATA packet from the server (RRQ transfer).
\* @type: $udpPacket => Bool;
ClientRecvDATA(_udp) ==
    ClientRecvDATA::
    LET ipPort == <<_udp.destIp, _udp.destPort>> IN
    /\ IsDATA(_udp.payload)
    /\ _udp.srcIp = SERVER_IP
    /\ ipPort \in DOMAIN clientTransfers
    /\  LET data == AsDATA(_udp.payload)
            transfer == clientTransfers[ipPort]
            \* Is it the first packet of the transfer? No OACK was received.
            isFirstPacket == data.blockNum = 1 /\ transfer.port = 69
            \* update the transfer state on the client side
            newTransfer ==
                IF ~isFirstPacket
                THEN [ transfer EXCEPT
                    !.blocks = Append(@, data.data),
                    !.blockNum = data.blockNum,
                    !.timestamp = clock,
                    !.transferred = @ + data.data
                ] ELSE [ transfer EXCEPT
                    !.port = _udp.srcPort,
                    \* since no options were negotiated, we use the defaults
                    !.tsize = -1,       \* transfer size is unknown
                    !.blksize = 512,    \* default block size
                    !.timeout = 255,    \* default timeout
                    !.blocks = Append(@, data.data),
                    !.blockNum = data.blockNum,
                    !.timestamp = clock,
                    !.transferred = @ + data.data
                ]
            \* the ACK packet to send over UDP
            ackPacket == [
                srcIp |-> _udp.destIp,
                srcPort |-> _udp.destPort,
                destIp |-> _udp.srcIp,
                destPort |-> _udp.srcPort,
                payload |-> ACK(data.blockNum)
            ]
        IN
        \* make sure that we receive from the correct port
        /\ ~isFirstPacket => (_udp.srcPort = transfer.port)
        \* do not receive packets if the connection must timeout
        /\ clock <= transfer.timestamp + transfer.timeout
        \* receive the block in order
        /\ data.blockNum = transfer.blockNum + 1
        /\ clientTransfers' = [ clientTransfers EXCEPT ![ipPort] = newTransfer ]
        \* TODO: close the connection when the last block is received
        \* send the ACK for the received DATA
        /\ packets' = packets \union { ackPacket }
        /\ lastAction' = ActionRecvSend(ackPacket)
    /\ UNCHANGED <<serverTransfers, clock>>

\* The server receives an ACK packet and sends DATA (RRQ transfer).
\* @type: $udpPacket => Bool;
ServerSendDATA(_udp) ==
    ServerSendDATA::
    LET ipPort == <<_udp.srcIp, _udp.srcPort>> IN
    /\ IsACK(_udp.payload)
    /\ _udp.destIp = SERVER_IP
    /\ ipPort \in DOMAIN serverTransfers
    /\  LET ack == AsACK(_udp.payload)
            transfer == serverTransfers[ipPort]
            dataSize == Min(transfer.blksize,
                             transfer.tsize - transfer.transferred)
            \* update the transfer state on the server side
            newTransfer == [ transfer EXCEPT
                !.transferred = @ + dataSize,
                !.timestamp = clock,
                !.blockNum = @ + 1
            ]
            \* the DATA packet to send over UDP
            dataPacket == [
                srcIp |-> _udp.destIp,
                srcPort |-> _udp.destPort,
                destIp |-> _udp.srcIp,
                destPort |-> _udp.srcPort,
                payload |-> DATA(transfer.blockNum + 1, dataSize)
            ]
        IN
        \* make sure that we receive from the correct port
        /\ _udp.destPort = transfer.port
        \* receive the block in order
        /\ ack.blockNum = transfer.blockNum
        \* do not receive packets if the connection must timeout
        /\ clock <= transfer.timestamp + transfer.timeout
        \* either we have more data to send, or we send exactly 0 bytes in the last block
        /\  \/ transfer.tsize > transfer.transferred
            \/ transfer.blockNum * transfer.blksize = transfer.tsize
        /\ serverTransfers' = [ serverTransfers EXCEPT ![ipPort] = newTransfer ]
        \* send the DATA for the next block
        /\ packets' = packets \union { dataPacket }
        /\ lastAction' = ActionRecvSend(dataPacket)
    /\ UNCHANGED <<clientTransfers, clock>>

\* The server receives an ACK packet and resends DATA that it sent in the past.
\* This is to fix the mismatch found by the test harness.
\* @type: $udpPacket => Bool;
ServerResendDATA(_udp) ==
    ServerResendDATA::
    LET ipPort == <<_udp.srcIp, _udp.srcPort>> IN
    /\ IsACK(_udp.payload)
    /\ _udp.destIp = SERVER_IP
    /\ ipPort \in DOMAIN serverTransfers
    /\  \E dataPacket \in packets:
        LET ack == AsACK(_udp.payload)
            data == AsDATA(dataPacket.payload)
            transfer == serverTransfers[ipPort]
        IN
        \* make sure that we receive from the correct port
        /\ _udp.destPort = transfer.port
        \* The DATA packet is sent in response to the ACK.
        /\ ack.blockNum + 1 = data.blockNum
        /\ dataPacket.srcIp = SERVER_IP
        /\ dataPacket.srcPort = _udp.destPort
        /\ dataPacket.destIp = _udp.srcIp
        /\ dataPacket.destPort = _udp.srcPort
        \* do not receive packets if the connection must timeout
        /\ clock <= transfer.timestamp + transfer.timeout
        \* only update the timestamp
        /\ serverTransfers' = [ serverTransfers EXCEPT ![ipPort].timestamp = clock ]
        /\ lastAction' = ActionRecvSend(dataPacket)
    /\ UNCHANGED <<packets, clientTransfers, clock>>

\* The server receives an ACK packet and closes the connection (RRQ transfer).
\* @type: $udpPacket => Bool;
ServerRecvAckAndCloseConn(_udp) ==
    ServerRecvAckAndCloseConn::
    LET ipPort == <<_udp.srcIp, _udp.srcPort>> IN
    /\ IsACK(_udp.payload)
    /\ _udp.destIp = SERVER_IP
    /\ ipPort \in DOMAIN serverTransfers
    /\  LET ack == AsACK(_udp.payload)
            transfer == serverTransfers[ipPort]
        IN
        \* make sure that we receive from the correct port
        /\ _udp.destPort = transfer.port
        \* receive the block in order
        /\ ack.blockNum = transfer.blockNum
        \* do not receive packets if the connection must timeout
        /\ clock <= transfer.timestamp + transfer.timeout
        \* either we have more data to send, or we send exactly 0 bytes in the last block
        /\ transfer.tsize = transfer.transferred
        \* close the connection
        /\ serverTransfers' = [ p \in DOMAIN serverTransfers \ { ipPort } |->
                serverTransfers[p]
            ]
    /\ lastAction' = ActionRecvClose(_udp)
    /\ UNCHANGED <<packets, clientTransfers, clock>>

(************************** Error handling ******************************)

\* The server receives an ERROR packet and closes the connection.
\* @type: $udpPacket => Bool;
ServerRecvErrorAndCloseConn(_udp) ==
    ServerRecvErrorAndCloseConn::
    LET ipPort == <<_udp.srcIp, _udp.srcPort>> IN
    /\  IsERROR(_udp.payload)
    /\  _udp.destIp = SERVER_IP
    /\  ipPort \in DOMAIN serverTransfers
    /\  LET error == AsERROR(_udp.payload)
            transfer == serverTransfers[ipPort]
        IN
        \* make sure that we receive from the correct port
        /\ _udp.destPort = transfer.port
        \* close the connection
        /\ serverTransfers' = [
                p \in DOMAIN serverTransfers \ { ipPort } |->
                    serverTransfers[p]
            ]
    /\ lastAction' = ActionRecvClose(_udp)
    /\ UNCHANGED <<packets, clientTransfers, clock>>

\* The client receives an ERROR packet and closes the connection.
\* @type: $udpPacket => Bool;
ClientRecvErrorAndCloseConn(_udp) ==
    ClientRecvErrorAndCloseConn::
    LET ipPort == <<_udp.srcIp, _udp.srcPort>> IN
    /\  IsERROR(_udp.payload)
    /\  _udp.destIp = SERVER_IP
    /\  ipPort \in DOMAIN clientTransfers
    /\  LET error == AsERROR(_udp.payload)
            transfer == clientTransfers[ipPort]
        IN
        \* make sure that we receive from the correct port
        /\ _udp.srcPort = transfer.port
        \* close the connection
        /\ clientTransfers' = [
                p \in DOMAIN clientTransfers \ { ipPort } |->
                    clientTransfers[p]
            ]
    /\ lastAction' = ActionRecvClose(_udp)
    /\ UNCHANGED <<packets, serverTransfers, clock>>

(********************* Ignore outdated packets ***************************)
\* The server sends an outdated packet (after timeout).
\* @type: $udpPacket => Bool;
ServerSendOutdated(_udp) ==
    ServerSendOutdated::
    LET ipPort == <<_udp.srcIp, _udp.srcPort>> IN
    /\  _udp.destIp = SERVER_IP
    /\  ipPort \in DOMAIN serverTransfers =>
            LET transfer == serverTransfers[ipPort] IN
            (clock > transfer.timestamp + transfer.timeout)
    /\ lastAction' = ActionServerSendOutdated(_udp)
    /\ UNCHANGED <<packets, serverTransfers, clientTransfers, clock>>

(******************************* Time ***********************************)

\* Advance the global clock by some delta in the range [1, 255].
\* The choice of the interval is dictated by the TFTP timeout option range.
AdvanceClock(delta) ==
    AdvanceClock::
    /\ clock' = clock + delta
    /\ lastAction' = ActionAdvanceClock(delta)
    /\ UNCHANGED <<packets, serverTransfers, clientTransfers>>

\* The server drops a connection due to timeout.
ServerTimeout(ipPort) ==
    ServerTimeout::
    /\ ipPort \in DOMAIN serverTransfers
    /\ LET transfer == serverTransfers[ipPort] IN
        /\ clock > transfer.timestamp + transfer.timeout
        /\ serverTransfers' = [ p \in DOMAIN serverTransfers \ { ipPort } |->
                serverTransfers[p]
            ]
    /\ lastAction' = ActionServerTimeout(ipPort)
    /\ UNCHANGED <<packets, clientTransfers, clock>>

\* A client drops a connection due to timeout.
ClientTimeout(ipPort) ==
    ClientTimeout::
    /\ ipPort \in DOMAIN clientTransfers
    /\ LET transfer == clientTransfers[ipPort] IN
        /\ clock > transfer.timestamp + transfer.timeout
        /\ clientTransfers' = [ p \in DOMAIN clientTransfers \ { ipPort } |->
                clientTransfers[p]
            ]
    /\ lastAction' = ActionClientTimeout(ipPort)
    /\ UNCHANGED <<packets, serverTransfers, clock>>

(********************* The Next-state relation **************************)

Next ==
    \* the actions by the clients
    \/  \E srcIp \in CLIENT_IPS, srcPort \in PORTS:
            \E filename \in DOMAIN FILES, timeout \in 1..255:
                \* "man tftpd": 65464 is the theoretical maximum for block size
                \* https://linux.die.net/man/8/tftpd
                \E tsize \in 0..FILES[filename], blksize \in 0..65464:
                    \* choose a subset of the options to request
                    \E optionKeys \in SUBSET OPTIONS_RFC2349:
                        LET options ==
                            mk_options(optionKeys, blksize, tsize, timeout)
                        IN
                        ClientSendRRQ(srcIp, srcPort, filename, options)
    \/  \E udp \in packets:
            \/ ClientRecvDATA(udp)
            \/ ClientRecvOACK(udp)
            \/ ClientRecvErrorAndCloseConn(udp)
    \/  \E ipPort \in DOMAIN clientTransfers:
            ClientTimeout(ipPort)
    \* the server
    \/  \E udp \in packets:
            \/ ServerRecvRRQ(udp)
            \/ ServerSendDATA(udp)
            \/ ServerResendDATA(udp)
            \/ ServerRecvAckAndCloseConn(udp)
            \/ ServerRecvErrorAndCloseConn(udp)
            \/ ServerSendOutdated(udp)
    \/  \E ipPort \in DOMAIN serverTransfers:
            ServerTimeout(ipPort)
    \* handle the clock and timeouts
    \/  \E delta \in 1..255:
            AdvanceClock(delta)

===============================================================================