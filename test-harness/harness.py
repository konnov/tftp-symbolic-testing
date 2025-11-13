#!/usr/bin/env python3
"""
TFTP Test Harness - Main orchestrator for symbolic testing of TFTP protocol.

This script:
1. Starts the Apalache server
2. Loads the TFTP specification
3. Generates test runs by exploring symbolic executions
4. Controls Docker containers running the TFTP server and clients
5. Executes TFTP operations and validates against the specification

Claude Sonnet 4.5 and Igor Konnov, 2025
"""

from collections import namedtuple
from copy import deepcopy
from dataclasses import asdict, dataclass, is_dataclass
import json
import logging
import orjson
import os
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from itf_py import Trace, itf_variant, trace_from_json, value_to_json

from client import (
    JsonRpcClient,
    AssumptionDisabled,
    AssumptionEnabled,
    TransitionEnabled,
    TransitionDisabled,
)
from docker_manager import DockerManager
from server import ApalacheServer

# Error messages as per RFC 1350 and RFC 2347
ERROR_MESSAGES = {
    0: "Not defined",
    1: "File not found",
    2: "Access violation",
    3: "Disk full or allocation exceeded",
    4: "Illegal TFTP operation",
    5: "Unknown transfer ID",
    6: "File already exists",
    7: "No such user",
    8: "Option negotiation failed"
}


# Variant type dataclasses for TLA+ types
# Class names must match variant tags exactly (required by itf-py)

@itf_variant
@dataclass
class OACK:
    """TFTP OACK (Option Acknowledgment) packet variant."""
    opcode: int
    options: Dict[str, int]


@itf_variant
@dataclass
class DATA:
    """TFTP DATA packet variant."""
    opcode: int
    blockNum: int
    data: int


@itf_variant
@dataclass
class ACK:
    """TFTP ACK (Acknowledgment) packet variant."""
    opcode: int
    blockNum: int


@itf_variant
@dataclass
class ERROR:
    """TFTP ERROR packet variant."""
    opcode: int
    errorCode: int


@itf_variant
@dataclass
class ActionRecvSend:
    """Action representing receiving and sending packets."""
    rcvd: Any
    sent: Any


# The labels of the spec actions that are controlled by the tester.
# The other labels are controlled by the SUT (TFTP server).
TESTER_ACTION_LABELS = frozenset([
    "Init", "ClientSendRRQ", "ClientTimeout",
    "ClientRecvOACKthenSendAck", "ClientRecvOACKthenSendError",
    "ClientRecvDATA", "AdvanceClock", "ClientRecvErrorAndCloseConn"
])

TESTER = "tester"
SUT = "sut"


class TftpTestHarness:
    """Main test harness for TFTP protocol testing."""

    def __init__(self, spec_dir: str, output_dir: str, log_dir: str):
        """
        Initialize the test harness.

        Args:
            spec_dir: Directory containing TLA+ specifications
            output_dir: Directory to save test results
            log_dir: Directory for log files
        """
        self.spec_dir = Path(spec_dir)
        self.output_dir = Path(output_dir)
        self.log_dir = Path(log_dir)

        # Create directories if they don't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Setup logging
        self.setup_logging()

        # Apalache server and client
        self.server = None
        self.client = None

        # Docker manager
        self.docker = None

        # Specification parameters
        self.spec_params = None
        self.current_snapshot = None

        # Test run tracking
        self.test_run_number = 0
        self.current_transitions = []
        self.command_log = []

    def setup_logging(self):
        """Configure logging for the harness."""
        log_file = self.log_dir / f"harness_{time.strftime('%Y%m%d_%H%M%S')}.log"

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )

        self.log = logging.getLogger(__name__)
        self.log.info(f"Test harness initialized. Logging to {log_file}")

        # Keep track of per-run log handlers for cleanup
        self.run_log_handlers = []

    def start_apalache(self, hostname: str = "localhost", port: int = 8822):
        """Start the Apalache server."""
        self.log.info("Starting Apalache server...")
        self.server = ApalacheServer(str(self.log_dir), hostname, port)

        if not self.server.start_server():
            self.log.error("Failed to start Apalache server")
            return False

        self.log.info("Apalache server started successfully")
        return True

    def stop_apalache(self):
        """Stop the Apalache server."""
        if self.server:
            self.log.info("Stopping Apalache server...")
            self.server.stop_server()

    def setup_docker(self) -> bool:
        """Set up the Docker environment for TFTP testing."""
        self.log.info("Setting up Docker environment...")

        # Initialize Docker manager
        self.docker = DockerManager(str(self.spec_dir.parent / "test-harness"))

        # Set up Docker (build image, create network, start containers)
        if not self.docker.setup():
            self.log.error("Failed to set up Docker environment")
            return False

        self.log.info("Docker environment ready")
        return True

    def cleanup_docker(self):
        """Clean up Docker resources."""
        if self.docker:
            self.log.info("Cleaning up Docker environment...")
            self.docker.cleanup()

        # Clean up any remaining log handlers
        if hasattr(self, 'run_log_handlers'):
            root_logger = logging.getLogger()
            for handler in self.run_log_handlers:
                root_logger.removeHandler(handler)
                handler.close()
            self.run_log_handlers.clear()

    def _construct_expected_packet(self, response: Dict[str, Any]) -> Any:
        """
        Construct an expected packet structure from Docker client response
        that matches the TLA+ specification format.

        Args:
            response: Response from Docker client containing packet details

        Returns:
            Expected packet as a namedtuple matching TLA+ $udpPacket type
        """
        # Extract packet details from response
        opcode = response.get('opcode')
        src_ip = response.get('src_ip', '')
        src_port = response.get('src_port', 0)
        dest_ip = response.get('dest_ip', '')
        dest_port = response.get('dest_port', 0)

        # Add payload based on opcode
        # Payload structure matches TLA+ Variant type with dataclass for value
        if opcode == 6:  # OACK
            options = response.get('options', {})
            # Convert string values to integers where applicable
            typed_options = {}
            for key, value in options.items():
                try:
                    typed_options[key] = int(value)
                except (ValueError, TypeError):
                    typed_options[key] = value

            # Create payload variant using module-level dataclass
            payload = OACK(
                opcode=6,
                options=typed_options
            )
        elif opcode == 3:  # DATA
            # Create payload variant using module-level dataclass
            payload = DATA(
                opcode=3,
                blockNum=response.get('block_num', 0),
                data=response.get('data_length', 0)
            )
        elif opcode == 4:  # ACK
            # Create payload variant using module-level dataclass
            payload = ACK(
                opcode=4,
                blockNum=response.get('block_num', 0)
            )
        elif opcode == 5:  # ERROR
            # Create payload variant using module-level dataclass
            payload = ERROR(
                opcode=5,
                errorCode=response.get('error_code', 0),
            )
        else:
            payload = None

        # Construct packet record using namedtuple (not dict)
        UdpPacketType = namedtuple("UdpPacket", ["srcIp", "srcPort", "destIp", "destPort", "payload"])
        expected = UdpPacketType(
            srcIp=src_ip,
            srcPort=src_port,
            destIp=dest_ip,
            destPort=dest_port,
            payload=payload
        )

        return expected

    def _spec_labels_from_operation(self, operation: Dict[str, Any]) -> List[str]:
        """
        Generate the list of action labels that match the expected packet
        from an operation returned by `execute_tftp_operation`.

        Args:
            operation: Operation dictionary from execute_tftp_operation
        Returns:
            List of action label strings
        """
        if "timeout_occurred" in operation and operation["timeout_occurred"]:
            # Let the protocol spec match the timeout.
            return [ 'ServerTimeout' ]

        # Check if operation has an expected_packet
        if not operation or 'packet_from_server' not in operation:
            return []

        packet = operation['packet_from_server']
        # For namedtuples, access payload as an attribute
        payload = packet.payload if hasattr(packet, 'payload') else None

        # Check if payload exists and get its type name (for namedtuples)
        if not payload:
            return []

        # For namedtuples, the type name is the tag
        if hasattr(payload, '__class__'):
            tag = type(payload).__name__
        else:
            return []

        if tag == 'DATA':
            return ['ServerRecvRRQthenSendData', 'ServerSendDATA', 'ServerResendDATA']
        elif tag == 'OACK':
            return ['ServerRecvRRQthenSendOack']
        elif tag == 'ERROR':
            return ['ServerRecvRRQthenSendError']
        # TODO: handle 'ACK' when we deal with WRQ

        return []

    def load_specification(self, solver_timeout: int = 300):
        """Load the TFTP specification into Apalache."""
        self.log.info("Loading TFTP specification...")

        # Initialize JSON-RPC client
        self.client = JsonRpcClient(
            hostname="localhost",
            port=8822,
            solver_timeout=solver_timeout
        )

        # Specification files
        spec_files = [
            str(self.spec_dir / "MC2_tftp.tla"),
            str(self.spec_dir / "typedefs.tla"),
            str(self.spec_dir / "util.tla"),
            str(self.spec_dir / "tftp.tla"),
        ]

        # Load the specification
        self.spec_params = self.client.load_spec(
            sources=spec_files,
            init="Init",
            next="Next",
            invariants=["TrueInv"],
            view="MeasureView"
        )

        if not self.spec_params:
            self.log.error("Failed to load specification")
            return False

        self.current_snapshot = self.spec_params['snapshot_id']
        self.log.info(f"Specification loaded. Snapshot ID: {self.current_snapshot}")
        self.log.info(f"{len(self.spec_params['init'])} init transitions")
        for trans in self.spec_params['init']:
            index = trans['index']
            labels = ','.join(trans.get('labels', []))
            self.log.info(f"  Init {index} [{labels}]")

        self.log.info(f"{len(self.spec_params['next'])} next transitions")
        for trans in self.spec_params['next']:
            index = trans['index']
            labels = ','.join(trans.get('labels', []))
            self.log.info(f"  Next {index} [{labels}]")

        return True

    def try_spec_transition(self, transition: Dict['str', Any]) -> bool:
        """
        Try to assume a transition and check if it's enabled.

        Args:
            transition: Transition dictionary as returned by load_spec

        Returns:
            True if the transition is enabled, False otherwise
        """
        if not self.client:
            raise RuntimeError("Client not initialized")

        transition_id = transition['index']
        labels = ','.join(transition.get('labels', []))
        self.log.info(f"Trying transition {transition_id} [{labels}]...")

        result = self.client.assume_transition(transition_id, check_enabled=True)

        if isinstance(result, TransitionEnabled):
            self.log.info(f"Transition {transition_id} is ENABLED")
            return True
        elif isinstance(result, TransitionDisabled):
            self.log.info(f"Transition {transition_id} is DISABLED")
            return False
        else:
            self.log.warning(f"Transition {transition_id} status is UNKNOWN")
            return False

    def execute_sut_operation(self, transition_id: int) -> Optional[Dict[str, Any]]:
        """
        Execute the TFTP operation corresponding to the transition in SUT.

        Args:
            transition_id: The transition that was enabled

        Returns:
            Dictionary containing the operation details and response
        """
        if not self.client:
            raise RuntimeError("Client not initialized")

        self.log.info(f"Executing TFTP operation for transition {transition_id}")

        # Query Apalache for the transition details using TRACE
        try:
            trace_result = self.client.query(kinds=["TRACE"])
            trace_json = trace_result.get('trace', {})

            # Decode the ITF trace using itf-py
            # The trace follows ITF format (ADR-015): https://apalache-mc.org/docs/adr/015adr-trace.html
            trace = trace_from_json(trace_json)
            self.log.info(f"Retrieved trace with {len(trace.states)} states")

            if trace.states:
                # Get the last state in the trace
                current_state = trace.states[-1]
                state_index = current_state.meta.get('index', '?')
                state_values = current_state.values

                self.log.debug(f"Current state index: {state_index}")
                self.log.debug(f"Current state keys: {state_values.keys()}")

                # Extract lastAction from the state
                last_action = state_values.get('lastAction')
                if last_action is None:
                    self.log.warning("No lastAction in current state")
                    return None

                # With itf-py 0.4.1+, variants are decoded as typed namedtuples
                # The type name is the tag (e.g., 'ActionInit', 'ActionClientSendRRQ')
                action_tag = type(last_action).__name__
                self.log.debug(f"lastAction type: {action_tag}")
                self.log.debug(f"lastAction fields: {last_action._fields if hasattr(last_action, '_fields') else 'N/A'}")

                # Determine the TFTP operation based on the action tag
                operation = {
                    'transition_id': transition_id,
                    'timestamp': time.time(),
                    'action_tag': action_tag,
                    'action_value': last_action,
                }

                # Parse the action to determine what TFTP command to send
                if action_tag == 'ActionInit':
                    self.log.info("Action: Initialization")
                    operation['command'] = 'init'

                elif action_tag == 'ActionClientSendRRQ':
                    self.log.info("Action: Client sends RRQ")
                    sent_packet = last_action.sent
                    operation['command'] = 'send_rrq'

                    # Send RRQ command to Docker client
                    if self.docker:
                        # Extract packet details (itf-py decoded namedtuples)
                        src_ip = sent_packet.srcIp
                        src_port = sent_packet.srcPort
                        dest_ip = sent_packet.destIp
                        dest_port = sent_packet.destPort
                        payload = sent_packet.payload

                        # Extract RRQ details from payload
                        # payload is a namedtuple for RRQ variant
                        payload_data = payload.value if hasattr(payload, 'value') else payload
                        filename = payload_data.filename
                        mode = payload_data.mode
                        options = payload_data.options if hasattr(payload_data, 'options') else {}

                        # Build command for Docker client
                        # Note: client expects 'type': 'rrq', not 'action': 'send_rrq'
                        command = {
                            'type': 'rrq',
                            'filename': filename,
                            'mode': mode,
                            'options': dict(options) if hasattr(options, 'items') else {},
                            'source_port': src_port  # Optional: client can use specific source port
                        }

                        response = self.docker.send_command_to_client(src_ip, command)
                        if response:
                            operation['response'] = response

                            # Decode response and construct expected packet for TLA+ validation
                            # Check for 'opcode' which indicates a valid TFTP packet (including ERROR)
                            if 'opcode' in response:
                                expected_packet = self._construct_expected_packet(response)
                                operation['packet_from_server'] = expected_packet
                                operation['packet_to_server'] = sent_packet
                                self.log.info(f"Expected packet for validation: {expected_packet}")
                            elif 'error' in response:
                                # Docker client error (not a TFTP ERROR packet)
                                self.log.error(f"Docker client error: {response['error']}")
                        else:
                            self.log.warning("No response from Docker client")
                    else:
                        self.log.warning("Docker manager not initialized, skipping actual TFTP operation")

                elif action_tag == 'ActionRecvSend':
                    rcvd_packet = last_action.rcvd
                    sent_packet = last_action.sent
                    self.log.info(f"Action: Receive and Send")
                    self.log.info(f"  Received packet: {rcvd_packet}")
                    self.log.info(f"  Sent packet: {sent_packet}")
                    operation['command'] = 'recv_send'
                    operation['rcvd_packet'] = rcvd_packet
                    operation['sent_packet'] = sent_packet

                    # Determine the specific recv/send operation based on packet types
                    rcvd_payload_type = type(rcvd_packet.payload).__name__ if hasattr(rcvd_packet, 'payload') and rcvd_packet.payload else None
                    sent_payload_type = type(sent_packet.payload).__name__ if hasattr(sent_packet, 'payload') and sent_packet.payload else None

                    self.log.info(f"  Received payload type: {rcvd_payload_type}")
                    self.log.info(f"  Sent payload type: {sent_payload_type}")

                    # Handle OACK received → ACK sent (client acknowledges option negotiation)
                    if rcvd_payload_type == 'OACK' and sent_payload_type == 'ACK':
                        self.log.info("  → Client receives OACK and sends ACK")

                        if self.docker:
                            # Extract packet details
                            src_ip = sent_packet.srcIp
                            src_port = sent_packet.srcPort
                            dest_port = sent_packet.destPort
                            ack_payload = sent_packet.payload

                            # Extract ACK block number
                            block_num = ack_payload.blockNum

                            # Build ACK command for Docker client
                            command = {
                                'type': 'ack',
                                'block_num': block_num,
                                'dest_port': dest_port,
                                'source_port': src_port
                            }

                            self.log.info(f"  Sending ACK command to client: {command}")
                            response = self.docker.send_command_to_client(src_ip, command)

                            if response:
                                operation['response'] = response

                                # Check if we got a timeout
                                if response.get('timeout'):
                                    self.log.warning(f"  ⏱ Timeout waiting for server response after ACK")
                                    self.log.warning(f"  Server did not send DATA packet - connection may be closed")
                                    # Mark this as a timeout operation so turn switches to SUT
                                    # This allows the server timeout transition to be explored
                                    operation['timeout_occurred'] = True
                                elif 'error' in response:
                                    self.log.error(f"  ✗ Error from Docker client: {response['error']}")
                                elif 'opcode' in response:
                                    # We received a packet in response (e.g., DATA)
                                    self.log.info(f"  ✓ ACK response: {response}")
                                    expected_packet = self._construct_expected_packet(response)
                                    operation['packet_from_server'] = expected_packet
                                    operation['packet_to_server'] = sent_packet
                                    self.log.info(f"  Expected packet from server: {expected_packet}")
                                else:
                                    self.log.warning(f"  Unexpected response format: {response}")
                            else:
                                self.log.warning("  No response from Docker client")
                        else:
                            self.log.warning("  Docker manager not initialized, skipping actual operation")

                    # Handle OACK received → ERROR sent (client rejects option negotiation)
                    elif rcvd_payload_type == 'OACK' and sent_payload_type == 'ERROR':
                        self.log.info("  → Client receives OACK and sends ERROR")

                        if self.docker:
                            # Extract packet details
                            src_ip = sent_packet.srcIp
                            src_port = sent_packet.srcPort
                            dest_port = sent_packet.destPort
                            error_payload = sent_packet.payload

                            # Extract ERROR details
                            error_code = error_payload.errorCode
                            error_msg = ERROR_MESSAGES.get(error_code, f"Error code {error_code}")

                            # Build ERROR command for Docker client
                            command = {
                                'type': 'error',
                                'error_code': error_code,
                                'error_msg': error_msg,
                                'dest_port': dest_port,
                                'source_port': src_port
                            }

                            self.log.info(f"  Sending ERROR command to client: {command}")
                            response = self.docker.send_command_to_client(src_ip, command)

                            if response:
                                operation['response'] = response

                                # Check response status
                                if response.get('status') == 'error_sent':
                                    self.log.info(f"  ✓ ERROR sent successfully (code={error_code})")
                                    # ERROR packets don't expect a response - connection is closed
                                elif 'error' in response:
                                    self.log.error(f"  ✗ Error from Docker client: {response['error']}")
                                elif 'opcode' in response:
                                    # Unexpected: server sent a response to ERROR
                                    self.log.warning(f"  ⚠ Unexpected response to ERROR: {response}")
                                    expected_packet = self._construct_expected_packet(response)
                                    operation['packet_from_server'] = expected_packet
                                    operation['packet_to_server'] = sent_packet
                                    self.log.info(f"  Unexpected packet from server: {expected_packet}")
                                else:
                                    self.log.warning(f"  Unexpected response format: {response}")
                            else:
                                self.log.warning("  No response from Docker client")
                        else:
                            self.log.warning("  Docker manager not initialized, skipping actual operation")

                    # Handle DATA received → ACK sent (client acknowledges data block)
                    elif rcvd_payload_type == 'DATA' and sent_payload_type == 'ACK':
                        self.log.info("  → Client receives DATA and sends ACK")

                        if self.docker:
                            # Extract packet details
                            src_ip = sent_packet.srcIp
                            src_port = sent_packet.srcPort
                            dest_port = sent_packet.destPort
                            ack_payload = sent_packet.payload

                            # Extract ACK block number
                            block_num = ack_payload.blockNum

                            # Build ACK command for Docker client
                            command = {
                                'type': 'ack',
                                'block_num': block_num,
                                'dest_port': dest_port,
                                'source_port': src_port
                            }

                            self.log.info(f"  Sending ACK command to client: {command}")
                            response = self.docker.send_command_to_client(src_ip, command)

                            if response:
                                operation['response'] = response

                                # Check if we got a timeout
                                if response.get('timeout'):
                                    self.log.warning(f"  ⏱ Timeout waiting for server response after ACK")
                                    self.log.info(f"  This may be normal if all data blocks received")
                                    # Mark this as a timeout operation so turn switches to SUT
                                    operation['timeout_occurred'] = True
                                elif 'error' in response:
                                    self.log.error(f"  ✗ Error from Docker client: {response['error']}")
                                elif 'opcode' in response:
                                    # We received another packet (e.g., next DATA block)
                                    self.log.info(f"  ✓ ACK response: {response}")
                                    expected_packet = self._construct_expected_packet(response)
                                    operation['packet_from_server'] = expected_packet
                                    operation['packet_to_server'] = sent_packet
                                    self.log.info(f"  Expected packet from server: {expected_packet}")
                                else:
                                    self.log.warning(f"  Unexpected response format: {response}")
                            else:
                                self.log.warning("  No response from Docker client")
                        else:
                            self.log.warning("  Docker manager not initialized, skipping actual operation")

                    else:
                        # TODO: Handle other recv/send combinations (DATA→ACK, etc.)
                        self.log.warning(f"  Unhandled recv/send combination: {rcvd_payload_type} → {sent_payload_type}")


                elif action_tag == 'ActionRecvClose':
                    rcvd_packet = last_action.rcvd
                    self.log.info(f"Action: Receive and Close")
                    self.log.info(f"  Received packet: {rcvd_packet}")
                    operation['command'] = 'recv_close'
                    operation['rcvd_packet'] = rcvd_packet
                    # TODO: Close the connection

                elif action_tag == 'ActionClientTimeout':
                    ip_port = last_action.ipPort
                    self.log.info(f"Action: Client Timeout on {ip_port}")
                    operation['command'] = 'client_timeout'
                    operation['ip_port'] = ip_port
                    # TODO: Handle client timeout

                elif action_tag == 'ActionServerTimeout':
                    ip_port = last_action.ipPort
                    self.log.info(f"Action: Server Timeout on {ip_port}")
                    operation['command'] = 'server_timeout'
                    operation['ip_port'] = ip_port
                    # TODO: Handle server timeout

                elif action_tag == 'ActionAdvanceClock':
                    delta = last_action.delta
                    self.log.info(f"Action: Advance Clock by {delta}")
                    operation['command'] = 'advance_clock'
                    operation['delta'] = delta

                    # Sleep for the specified duration to simulate time passing.
                    # TODO: It would be nicer to have clock manipulation in the SUT directly.
                    self.log.info(f"  Sleeping for {delta} seconds to advance clock...")
                    time.sleep(delta)
                    self.log.info(f"  ✓ Clock advanced by {delta} seconds")

                else:
                    self.log.warning(f"Unknown action tag: {action_tag}")
                    operation['command'] = 'unknown'

                return operation
            else:
                self.log.warning("Empty trace received")
                return None

        except Exception as e:
            self.log.error(f"Error querying transition details: {e}", exc_info=True)
            return None

    def save_test_run(self):
        """Save the current test run to disk."""
        # Note: test_run_number is already incremented and run_dir created in generate_test_run()
        run_dir = self.output_dir / f"run_{self.test_run_number:04d}"

        # Save transitions
        transitions_file = run_dir / "transitions.txt"
        with open(transitions_file, 'w') as f:
            f.write(','.join(map(str, self.current_transitions)))

        # This serializer is generated by Claude.
        # Can we make it simpler?
        def default(obj):
            """Custom serializer for orjson to handle itf-py and dataclass objects."""
            # --- Dataclasses ---
            if is_dataclass(obj):
                tag = getattr(obj.__class__, "__name__", None) # type: ignore
                return {"tag": tag, **asdict(obj)} # type: ignore

            # --- Namedtuples (including itf-py variant types) ---
            if isinstance(obj, tuple) and hasattr(obj, "_fields"):
                tag = getattr(obj.__class__, "__name__", None)
                data = {f: default(getattr(obj, f)) for f in obj._fields} # type: ignore
                return {"tag": tag, **data}

            # --- Regular tuples (e.g., <<Str, Int>> for ipPort) ---
            if isinstance(obj, tuple):
                return [default(item) for item in obj]

            # --- itf-py ImmutableList (including UdpPacket tuples) ---
            if type(obj).__name__ == 'ImmutableList':
                # Special case: 5-element list is a UdpPacket tuple
                # Format: [srcIp, srcPort, payload, destIp, destPort]
                if len(obj) == 5 and isinstance(obj[1], int) and isinstance(obj[4], int):
                    return {
                        "tag": "UdpPacket",
                        "srcIp": obj[0],
                        "srcPort": obj[1],
                        "payload": default(obj[2]),
                        "destIp": obj[3],
                        "destPort": obj[4]
                    }
                # Otherwise, convert to regular list
                return [default(item) for item in obj]

            # --- Regular lists ---
            if isinstance(obj, list):
                # Special case: 5-element list is a UdpPacket tuple
                if len(obj) == 5 and isinstance(obj[1], int) and isinstance(obj[4], int):
                    return {
                        "tag": "UdpPacket",
                        "srcIp": obj[0],
                        "srcPort": obj[1],
                        "payload": default(obj[2]),
                        "destIp": obj[3],
                        "destPort": obj[4]
                    }
                return [default(item) for item in obj]

            # --- itf-py FrozenDict ---
            if hasattr(obj, "items") and not isinstance(obj, dict):
                return {k: default(v) for k, v in obj.items()} # type: ignore

            # --- Dicts ---
            if isinstance(obj, dict):
                return {k: default(v) for k, v in obj.items()}

            # --- Primitives (let orjson handle them) ---
            if isinstance(obj, (int, str, bool, float, type(None))):
                return obj

            # --- Fallback ---
            raise TypeError(f"Type {type(obj)} not serializable")

        # Save commands and responses using orjson
        commands_file = run_dir / "commands.json"
        with open(commands_file, 'wb') as f:
            f.write(orjson.dumps(
                self.command_log,
                option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS | orjson.OPT_PASSTHROUGH_DATACLASS,
                default=default,
            ))

        # Save TFTP server logs if Docker is being used
        if self.docker:
            server_logs_file = run_dir / "tftpd_server.log"
            server_logs = self.docker.get_server_logs()
            with open(server_logs_file, 'w') as f:
                f.write(server_logs)
            self.log.info(f"TFTP server logs saved to {server_logs_file}")

            # Save syslog from the server container
            syslog_file = run_dir / "tftpd_syslog.log"
            syslog_content = self.docker.get_syslog()
            with open(syslog_file, 'w') as f:
                f.write(syslog_content)
            self.log.info(f"TFTP server syslog saved to {syslog_file}")

        self.log.info(f"=== Test run {self.test_run_number} completed and saved to {run_dir} ===")

        # Remove the run-specific log handler and close it
        if self.run_log_handlers:
            handler = self.run_log_handlers.pop()
            root_logger = logging.getLogger()
            root_logger.removeHandler(handler)
            handler.close()

        # Reset for next run
        self.current_transitions = []
        self.command_log = []

    def generate_test_run(self, max_steps: int = 20) -> bool:
        """
        Generate a single test run by exploring symbolic execution.

        Args:
            max_steps: Maximum number of steps in the test run
            max_retries: Maximum retries per step to find an enabled transition

        Returns:
            True if test run was successfully generated
        """
        if not self.client or not self.spec_params:
            raise RuntimeError("Client or spec_params not initialized")

        # Set up logging for this test run
        # Increment run number and create directory
        self.test_run_number += 1
        run_dir = self.output_dir / f"run_{self.test_run_number:04d}"
        run_dir.mkdir(parents=True, exist_ok=True)

        # Add a file handler for this specific test run
        run_log_file = run_dir / "python_harness.log"
        run_handler = logging.FileHandler(run_log_file)
        run_handler.setLevel(logging.INFO)
        run_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        # Get the root logger and add the handler
        root_logger = logging.getLogger()
        root_logger.addHandler(run_handler)
        self.run_log_handlers.append(run_handler)

        self.log.info(f"=== Starting test run generation {self.test_run_number} (max {max_steps} steps) ===")

        # Initialize with a random init transition
        # TODO: In this case, there is only one init transition,
        # in other projects there may be more
        init_transitions = self.spec_params['init']
        if not init_transitions:
            self.log.error("No init transitions available")
            return False

        init_trans = random.choice(init_transitions)
        self.log.debug(f"Selected init transition: {init_trans}")

        if not self.try_spec_transition(init_trans):
            self.log.error("Init transition is not enabled")
            return False

        self.current_transitions.append(init_trans)

        # Move to next step
        self.current_snapshot = self.client.next_step()

        # Main exploration loop
        next_transitions = self.spec_params['next']

        turn = TESTER               # Track whose turn it is: tester or SUT.
        last_sut_feedback = None    # The last operation received from SUT.
        stop_test = False           # Something went wrong, stop the test?
        for step in range(max_steps):
            if stop_test:
                break

            self.log.info(f"\n--- Step {step + 1}/{max_steps} ---")
            enabled_found = False

            # Try to find an enabled transition by the player whose turn it is.
            # Only use the transitions that match the current turn.
            if turn == TESTER:
                transitions_to_try = [ trans for trans in next_transitions \
                    if frozenset(trans.get("labels")).intersection(TESTER_ACTION_LABELS)
                ]
            else:
                op_labels = self._spec_labels_from_operation(last_sut_feedback) if last_sut_feedback else []
                transitions_to_try = [ trans for trans in next_transitions \
                    if any(label in op_labels for label in trans.get("labels", []))
                ]

            while len(transitions_to_try) > 0 and not enabled_found and not stop_test:
                # Select a random next transition from the transitions we have not tried yet
                next_trans = random.choice(transitions_to_try)
                transitions_to_try.remove(next_trans)

                # Save current snapshot before trying
                snapshot_before = self.current_snapshot

                # Try the transition in Apalache
                if not self.try_spec_transition(next_trans):
                    # Transition was disabled, rollback and try another
                    if snapshot_before is not None:
                        self.log.info(f"Rollback to snapshot {snapshot_before}")
                        self.client.rollback(snapshot_before)
                        self.current_snapshot = snapshot_before
                else:
                    # Move to next step in Apalache
                    self.current_snapshot = self.client.next_step()

                    if turn == TESTER:
                        enabled_found = True
                        self.current_transitions.append(next_trans)
                        # Execute the corresponding TFTP operation
                        last_sut_feedback = self.execute_sut_operation(next_trans["index"])
                        if last_sut_feedback:
                            self.command_log.append(last_sut_feedback)

                            if 'packet_from_server' in last_sut_feedback:
                                # We have received feedback from the SUT.
                                # Plan its evaluation for the next iteration.
                                turn = SUT
                            elif last_sut_feedback.get('timeout_occurred'):
                                # A timeout occurred - switch to SUT turn to allow
                                # server timeout transitions to be explored
                                self.log.info("  Switching to SUT turn to handle timeout")
                                turn = SUT
                    else:
                        if not last_sut_feedback:
                            self.log.error("No operation to validate on SUT turn")
                            return False

                        # Check if this is a timeout operation
                        if last_sut_feedback.get('timeout_occurred'):
                            # For timeout, we don't validate a packet - just switch back to TESTER
                            # The spec should have executed a timeout transition
                            self.log.info("  Timeout handled, switching back to TESTER turn")
                            turn = TESTER
                            last_sut_feedback = None
                            enabled_found = True
                            self.current_transitions.append(next_trans)
                        else:
                            # Normal case: validate the received packet
                            # Create the variant using module-level dataclass
                            expected_last_action = ActionRecvSend(
                                rcvd=last_sut_feedback['packet_to_server'],
                                sent=last_sut_feedback['packet_from_server']
                            )
                            self.log.info(f"Assume lastAction: {expected_last_action}")
                            # Assume that lastAction equals the reconstructed action
                            equalities = {
                                "lastAction": value_to_json(expected_last_action)
                            }
                            assume_result = self.client.assume_state(equalities, check_enabled=True)
                            if isinstance(assume_result, AssumptionEnabled):
                                self.log.info("✓ Received packet matches the spec")
                                turn = TESTER
                                last_sut_feedback = None
                                enabled_found = True
                                self.current_transitions.append(next_trans)
                                # save the current snapshot to remember the decision!
                                self.current_snapshot = assume_result.snapshot_id
                            elif isinstance(assume_result, AssumptionDisabled):
                                # Test found a discrepancy - this is valuable!
                                # However, we may have several SUT actions to try.
                                # Hence, do not break the loop yet.
                                # If we do not find a corresponding transition,
                                # we will break out by enabled_found = False.
                                enabled_found = False
                                # Transition was disabled, rollback and try another
                                if snapshot_before is not None:
                                    self.log.info(f"Rollback to snapshot {snapshot_before}")
                                    self.client.rollback(snapshot_before)
                                    self.current_snapshot = snapshot_before
                            else:
                                self.log.warning("? Unable to validate received packet")
                                stop_test = True

            if not enabled_found and not stop_test:
                if turn == SUT:
                    if last_sut_feedback and last_sut_feedback.get('timeout_occurred'):
                        # FIX #2: even if there was a timeout, a client should have a chance to
                        # receive a packet from the server (which may have been sent already!).
                        self.log.warning("✗ Last SUT timeout does NOT match the spec - continue")
                        stop_test = False # continue the test
                        turn = TESTER
                        last_sut_feedback = None
                    else:
                        self.log.warning("✗ Last SUT operation does NOT match the spec - test diverged!")
                        stop_test = True
                else:
                    self.log.warning(f"✗ Could not find enabled transition for tester - ending test run")
                    stop_test = True

        # Save the test run
        self.save_test_run()

        return True

    def run(self, num_tests: int = 1, max_steps: int = 20, use_docker: bool = False):
        """
        Main entry point for the test harness.

        Args:
            num_tests: Number of test runs to generate
            max_steps: Maximum steps per test run
            use_docker: Whether to use Docker for actual TFTP operations
        """
        try:
            # Start Apalache server
            if not self.start_apalache():
                self.log.error("Failed to start Apalache")
                return False

            # Load specification
            if not self.load_specification():
                self.log.error("Failed to load specification")
                return False

            # Optionally set up Docker
            if use_docker:
                if not self.setup_docker():
                    self.log.error("Failed to set up Docker")
                    return False

            # Generate test runs
            for i in range(num_tests):
                self.log.info(f"\n{'='*60}")
                self.log.info(f"Generating test run {i + 1}/{num_tests}")
                self.log.info(f"{'='*60}")

                # Rollback to initial state for each new test
                if self.client and self.spec_params:
                    self.client.rollback(self.spec_params['snapshot_id'])
                    self.current_snapshot = self.spec_params['snapshot_id']

                # Reset Docker containers to fresh state (similar to Apalache rollback)
                if use_docker and self.docker:
                    if not self.docker.reset_containers():
                        self.log.error("Failed to reset Docker containers")
                        return False

                self.generate_test_run(max_steps=max_steps)

            self.log.info(f"\n{'='*60}")
            self.log.info(f"Test generation complete. Generated {self.test_run_number} test runs")
            self.log.info(f"Results saved to {self.output_dir}")
            self.log.info(f"{'='*60}")

            return True

        except Exception as e:
            self.log.error(f"Error during test generation: {e}", exc_info=True)
            return False

        finally:
            # Cleanup
            if use_docker:
                self.cleanup_docker()

            if self.client:
                self.client.dispose_spec()
                self.client.close()

            self.stop_apalache()


def main():
    """Main entry point."""
    import argparse

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='TFTP Test Harness - Symbolic Testing')
    parser.add_argument('--docker', action='store_true',
                        help='Enable Docker for actual TFTP operations')
    parser.add_argument('--tests', type=int, default=10,
                        help='Number of test runs to generate (default: 10)')
    parser.add_argument('--steps', type=int, default=100,
                        help='Maximum steps per test run (default: 100)')
    args = parser.parse_args()

    # Configuration
    script_dir = Path(__file__).parent
    spec_dir = script_dir.parent / "spec"
    output_dir = script_dir / "test-results"
    log_dir = script_dir / "logs"

    # Create and run the harness
    harness = TftpTestHarness(
        spec_dir=str(spec_dir),
        output_dir=str(output_dir),
        log_dir=str(log_dir)
    )

    # Generate test runs
    success = harness.run(num_tests=args.tests, max_steps=args.steps, use_docker=args.docker)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
