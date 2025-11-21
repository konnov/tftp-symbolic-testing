#!/usr/bin/env python3
"""
TFTP Test Harness - Main orchestrator for symbolic testing of TFTP protocol.

This script:
1. Starts the Apalache server in Docker
2. Loads the TFTP specification
3. Generates test runs by exploring symbolic executions
4. Controls Docker containers running the TFTP server and clients
5. Executes TFTP operations and validates against the specification

The initial version by Claude Sonnet 4.5, 2025
Debugging and final refactoring by Igor Konnov, 2025
"""

from collections import namedtuple
from copy import deepcopy
from dataclasses import asdict, dataclass, is_dataclass
import json
import logging
from frozendict import frozendict
import orjson
import os
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from itf_py import Trace, itf_variant, trace_from_json, value_to_json

from apalache_rpc.client import (
    JsonRpcClient,
    AssumptionDisabled,
    AssumptionEnabled,
    TransitionEnabled,
    TransitionDisabled,
)
from docker_manager import DockerManager
import subprocess


class ImmutableDict(frozendict):
    """A wrapper around frozendict that displays dictionaries as
    `{k1: v_1, ..., k_n: v_n}`."""

    def __new__(cls, items: Dict[str, Any]) -> Any:
        return super().__new__(cls, items)


ImmutableDict.__str__ = (  # type: ignore
    dict.__str__
)  # use the default dict representation in pretty-printing

ImmutableDict.__repr__ = (  # type: ignore
    dict.__repr__
)  # use the default dict representation in pretty-printing


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
@dataclass(frozen=True)
class OACK:
    """TFTP OACK (Option Acknowledgment) packet variant."""
    opcode: int
    options: frozendict[str, int]


@itf_variant
@dataclass(frozen=True)
class DATA:
    """TFTP DATA packet variant."""
    opcode: int
    blockNum: int
    data: int


@itf_variant
@dataclass(frozen=True)
class ACK:
    """TFTP ACK (Acknowledgment) packet variant."""
    opcode: int
    blockNum: int


@itf_variant
@dataclass(frozen=True)
class ERROR:
    """TFTP ERROR packet variant."""
    opcode: int
    errorCode: int


@dataclass(frozen=True)
class UdpPacket:
    """TFTP UDP Packet structure as defined in the spec."""
    srcIp: str
    srcPort: int
    destIp: str
    destPort: int
    payload: Any


@itf_variant
@dataclass(frozen=True)
class ActionRecvSend:
    """Action representing receiving and sending packets."""
    sent: Any


# The labels of the spec actions that are controlled by the tester.
# The other labels are controlled by the SUT (TFTP server).
TESTER_ACTION_LABELS = frozenset([
    "Init",
    # the tester is obviously in control of the client actions
    "ClientSendRRQ", "ClientRecvOACKthenSendAck",
    "ClientRecvOACKthenSendError", "ClientRecvDATA",
    "ClientRecvErrorAndCloseConn", "ClientSendError",
    "ClientCrash", "ClientSendDup",
    # also, the tester controls passage of time
    "AdvanceClock",
    # these actions have to be handled by the tester as well,
    # as they are not related to the feedback from the SUT
    "ServerRecvAckAndCloseConn", "ServerRecvErrorAndCloseConn"
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
        self.transition_log = []
        self.sut_command_log = []
        # The list of feedback replies from SUT to process
        self.sut_feedback_to_process = set()

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

                # Set up per-run logging BEFORE any test run operations
                # Increment run number and create directory
                self.test_run_number += 1
                run_dir = self.get_run_dir()
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

    def replay_transitions(self, transitions_file: str, use_docker: bool = False) -> bool:
        """
        Replay transitions from a saved transitions.txt file.

        Args:
            transitions_file: Path to the transitions.txt file
            use_docker: Whether to use Docker for actual TFTP operations

        Returns:
            True if replay succeeded, False otherwise
        """
        try:
            # Read transitions from file
            transitions_path = Path(transitions_file)
            if not transitions_path.exists():
                self.log.error(f"Transitions file not found: {transitions_file}")
                return False

            self.log.info(f"Reading transitions from {transitions_file}")
            with open(transitions_path, 'r') as f:
                content = f.read().strip()
            
            # Parse the transitions - they're stored as Python dict syntax with single quotes
            # Format: {'index': 0, 'labels': ['Init']},{'index': 1, 'labels': ['Action1']},...
            # We need to evaluate them as Python literals
            import ast
            transitions = []
            for item_str in content.split('},{'):
                item_str = item_str.strip()
                if not item_str.startswith('{'):
                    item_str = '{' + item_str
                if not item_str.endswith('}'):
                    item_str = item_str + '}'
                # Use ast.literal_eval to safely parse Python dict syntax
                transitions.append(ast.literal_eval(item_str))
            
            self.log.info(f"Loaded {len(transitions)} transitions to replay")

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

            # Set up per-run logging
            self.test_run_number += 1
            run_dir = self.get_run_dir()
            run_dir.mkdir(parents=True, exist_ok=True)

            run_log_file = run_dir / "python_harness.log"
            run_handler = logging.FileHandler(run_log_file)
            run_handler.setLevel(logging.INFO)
            run_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

            root_logger = logging.getLogger()
            root_logger.addHandler(run_handler)
            self.run_log_handlers.append(run_handler)

            self.log.info(f"=== Replaying {len(transitions)} transitions ===")

            # Reset Docker containers to fresh state
            if use_docker and self.docker:
                if not self.docker.reset_containers():
                    self.log.error("Failed to reset Docker containers")
                    return False

            # Execute transitions one by one
            success = self._replay_transitions_sequence(transitions, run_dir, use_docker)

            # Save results
            if success:
                self.log.info(f"=== Replay completed successfully ===")
            else:
                self.log.warning(f"=== Replay diverged or failed ===")

            self.log.info(f"Results saved to {run_dir}")

            return success

        except Exception as e:
            self.log.error(f"Error during replay: {e}", exc_info=True)
            return False

        finally:
            # Cleanup
            if use_docker:
                self.cleanup_docker()

            if self.client:
                self.client.dispose_spec()
                self.client.close()

            self.stop_apalache()

    def _replay_transitions_sequence(self, transitions: List[Dict], run_dir: Path, use_docker: bool) -> bool:
        """
        Execute a sequence of transitions and compare with SUT behavior.

        Args:
            transitions: List of transition dictionaries with 'index' and 'labels'
            run_dir: Directory to save results
            use_docker: Whether Docker is being used

        Returns:
            True if all transitions executed successfully, False otherwise
        """
        # Start from initial state
        if not self.client or not self.spec_params:
            self.log.error("Specification not loaded")
            return False

        self.client.rollback(self.spec_params['snapshot_id'])
        self.current_snapshot = self.spec_params['snapshot_id']

        # Get initial transitions
        next_transitions = self.spec_params['next']
        
        step = 0
        stop_test = False
        
        for trans_info in transitions:
            if stop_test:
                break
                
            trans_index = trans_info['index']
            trans_labels = trans_info['labels']
            
            self.log.info(f"\n--- Replaying step {step + 1}: transition {trans_index} {trans_labels} ---")
            
            # Find the transition in next_transitions
            if trans_index >= len(next_transitions):
                self.log.error(f"Invalid transition index {trans_index}, only {len(next_transitions)} available")
                return False
            
            transition = next_transitions[trans_index]
            
            # Verify labels match
            if transition.get('labels') != trans_labels:
                self.log.warning(f"Label mismatch: expected {trans_labels}, got {transition.get('labels')}")
            
            # Try to execute this transition using assume_transition
            self.log.info(f"Trying transition {trans_index} {trans_labels}...")
            result = self.client.assume_transition(trans_index, check_enabled=True)
            
            if isinstance(result, TransitionDisabled):
                self.log.error(f"Transition {trans_index}: DISABLED (should be enabled for replay)")
                return False
            elif isinstance(result, TransitionEnabled):
                self.log.info(f"Transition {trans_index}: ENABLED")
                
                # Move to the next state
                self.current_snapshot = self.client.next_step()
                
                # Get the current action
                action = self.get_last_spec_action()
                if action:
                    self.log.info(f"  EXECUTE ACTION: {action}")
                    
                    # Execute the action if using Docker
                    if use_docker and self.docker:
                        # Execute TFTP operation based on action
                        self.execute_sut_operation(trans_index, action)
                        
                        # Check for SUT feedback
                        for src_ip in DockerManager.CLIENT_IPS:
                            cmd = {'type': 'get_packets'}
                            response = self.docker.send_command_to_client(src_ip, cmd)
                            if response:
                                for sut_packet in response.get('packets', []):
                                    spec_packet = self._spec_packet_from_sut_response(sut_packet)
                                    self.log.info(f"  SUT PACKET: {spec_packet}")
                
                step += 1
            else:
                self.log.error(f"Unexpected result type: {type(result)}")
                return False

        self.log.info(f"Successfully replayed {step} transitions")
        
        # Save the final trace
        trace_data = self.get_current_trace()
        if trace_data:
            trace_json, trace = trace_data
            trace_file = run_dir / "trace.itf.json"
            with open(trace_file, 'w') as f:
                json.dump(trace_json, f, indent=2)
            self.log.info(f"Trace saved to {trace_file}")
        
        # Save Docker logs if using Docker
        if use_docker and self.docker:
            # Save server logs
            server_logs_file = run_dir / "tftpd_server.log"
            server_logs = self.docker.get_server_logs()
            with open(server_logs_file, 'w') as f:
                f.write(server_logs)
            self.log.info(f"TFTP server logs saved to {server_logs_file}")

            # Save syslog
            syslog_file = run_dir / "tftpd_syslog.log"
            syslog_content = self.docker.get_syslog()
            with open(syslog_file, 'w') as f:
                f.write(syslog_content)
            self.log.info(f"TFTP server syslog saved to {syslog_file}")

            # Save client logs from all client containers
            for client_ip in DockerManager.CLIENT_IPS:
                client_logs_file = run_dir / f"tftp_client_{client_ip.split('.')[-1]}.log"
                client_logs = self.docker.get_client_logs(client_ip)
                with open(client_logs_file, 'w') as f:
                    f.write(client_logs)
                self.log.info(f"TFTP client logs for {client_ip} saved to {client_logs_file}")
        
        return True

    def generate_test_run(self, max_steps: int = 20) -> bool:
        """
        Generate a single test run by exploring symbolic execution.

        Args:
            max_steps: Maximum number of steps in the test run

        Returns:
            True if test run was successfully generated
        """
        if not self.client or not self.spec_params:
            raise RuntimeError("Client or spec_params not initialized")

        # Note: Per-run logging is set up in run() before calling this method

        # Initialize with a random init transition
        self.sut_feedback_to_process = set()
        init_transitions = self.spec_params['init']
        if not init_transitions:
            self.log.error("No init transitions available")
            return False

        init_trans = random.choice(init_transitions)
        self.log.debug(f"Selected init transition: {init_trans}")

        if not self.try_spec_transition(init_trans):
            self.log.error("Init transition is not enabled")
            return False

        self.transition_log.append(init_trans)

        # Move to next step
        self.current_snapshot = self.client.next_step()

        # Main exploration loop
        next_transitions = self.spec_params['next']

        turn = TESTER               # Track whose turn it is: tester or SUT.
        stop_test = False           # Something went wrong, stop the test?
        for step in range(max_steps):
            if stop_test:
                break

            self.log.info(f"\n--- Step {step + 1}/{max_steps} ---")
            enabled_found = False

            # Retrieve the new responses from the docker clients
            if self.docker:
                for src_ip in DockerManager.CLIENT_IPS:
                    cmd = { 'type': 'get_packets' }
                    response = self.docker.send_command_to_client(src_ip, cmd)
                    if response:
                        for sut_packet in response.get('packets', []):
                            # convert to spec packet format
                            spec_packet = self._spec_packet_from_sut_response(sut_packet)
                            self.log.info(f"  SUT PACKET: {spec_packet}")
                            self.sut_feedback_to_process.add(spec_packet)

            if self.sut_feedback_to_process:
                # give priority to SUT feedback
                # TODO: choose randomly!
                last_sut_feedback = self.sut_feedback_to_process.pop()
                turn = SUT
                op_labels = self._spec_labels_from_operation(last_sut_feedback) \
                    if last_sut_feedback else []
                transitions_to_try = [ trans for trans in next_transitions \
                    if any(label in op_labels for label in trans.get("labels", []))
                ]
            else:
                turn = TESTER
                transitions_to_try = [ trans for trans in next_transitions \
                    if frozenset(trans.get("labels")).intersection(TESTER_ACTION_LABELS)
                ]

            self.log.info(f"Turn: {turn}. {len(transitions_to_try)} transitions to try")

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
                        self.transition_log.append(next_trans)
                        # Before executing the SUT operation, recover lastAction
                        # and save it in the SMT context. This way, we do not diverge
                        # in the SMT context after executing the SUT operation.
                        # Otherwise, Z3 may return another model later.
                        last_action = self.get_last_spec_action()
                        if last_action:
                            equalities = { "lastAction": value_to_json(last_action) }
                            assume_result = self.client.assume_state(equalities, check_enabled=True)
                            if not isinstance(assume_result, AssumptionEnabled):
                                # This is a critical error - we just assumed lastAction from the model!
                                self.log.error("Failed to assume lastAction before after querying it from the model")
                                stop_test = True
                                break
                            # save the current snapshot to remember the decision!
                            self.current_snapshot = assume_result.snapshot_id
                            # Execute the corresponding TFTP operation
                            self.execute_sut_operation(next_trans["index"], last_action)
                    elif turn == SUT:
                        assert last_sut_feedback is not None, \
                            "last_sut_feedback should not be None on SUT turn"

                        # Normal case: validate the received packet
                        # Create the variant using module-level dataclass
                        expected_last_action = ActionRecvSend(sent=last_sut_feedback)
                        self.log.info(f"Assume lastAction: {expected_last_action}")
                        # Assume that lastAction equals the reconstructed action
                        equalities = {
                            "lastAction": value_to_json(expected_last_action)
                        }
                        assume_result = self.client.assume_state(equalities, check_enabled=True)
                        if isinstance(assume_result, AssumptionEnabled):
                            self.log.info(f"  EXECUTE ACTION: {expected_last_action}")
                            self.log.info("✓ Received packet matches the spec")
                            turn = TESTER
                            last_sut_feedback = None
                            enabled_found = True
                            self.transition_log.append(next_trans)
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
                if turn != SUT:
                    self.log.warning(f"✗ Could not find enabled transition for tester - ending test run")
                    stop_test = True
                else:
                    self.log.warning("✗ Last SUT operation does NOT match the spec - test diverged!")

                    # Save the current trace for debugging
                    try:
                        trace_data = self.get_current_trace()
                        if trace_data:
                            trace_json, _ = trace_data

                            # Save trace to file in the current run directory
                            run_dir = self.get_run_dir()
                            trace_file = run_dir / "divergence_trace.itf.json"
                            with open(trace_file, 'w') as f:
                                json.dump(trace_json, f, indent=2)
                            self.log.info(f"Saved divergence trace to {trace_file}")
                    except Exception as e:
                        self.log.error(f"Failed to save divergence trace: {e}", exc_info=True)

                    stop_test = True

        # Save the test run
        self.save_test_run()

        return True

    def execute_sut_operation(self, transition_id: int, last_spec_action: Any) -> Optional[Dict[str, Any]]:
        """
        Execute the TFTP operation corresponding to the transition in SUT.

        Args:
            transition_id: The transition that is enabled in the spec
            last_spec_action: The last action from the spec trace

        Returns:
            Dictionary containing the operation details and response
        """

        try:
            # With itf-py 0.4.1+, variants are decoded as typed namedtuples
            # The type name is the tag (e.g., 'ActionInit', 'ActionClientSendRRQ')
            action_tag = type(last_spec_action).__name__

            # Unified logging for all executed actions
            self.log.info(f"  EXECUTE ACTION: {last_spec_action}")

            # Determine the TFTP operation based on the action tag
            operation = {
                'transition_id': transition_id,
                'timestamp': time.time(),
                'action_tag': action_tag,
                'action_value': last_spec_action,
            }

            # Parse the action to determine what TFTP command to send
            if action_tag == 'ActionInit':
                self.log.info("TFTP operation for ActionInit")
                operation['command'] = 'init'
            elif action_tag == 'ActionClientSendRRQ':
                self.log.info("TFTP operation for ActionClientSendRRQ")
                sent_packet = last_spec_action.sent
                operation['command'] = 'send_rrq'

                # Send RRQ command to Docker client
                if self.docker:
                    # Extract packet details (itf-py decoded namedtuples)
                    src_ip = sent_packet.srcIp
                    src_port = sent_packet.srcPort
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
                        if 'error' in response:
                            # Docker client error (not a TFTP ERROR packet)
                            self.log.error(f"Docker client error: {response['error']}")
                    else:
                        self.log.warning("No response from Docker client")
                else:
                    self.log.warning("Docker manager not initialized, skipping actual TFTP operation")
            elif action_tag == 'ActionRecvSend':
                sent_packet = last_spec_action.sent
                self.log.info("TFTP operation for ActionRecvSend")
                self.log.info(f"  Sent packet: {sent_packet}")
                operation['command'] = 'recv_send'
                operation['sent_packet'] = sent_packet

                # Determine the specific recv/send operation based on packet types
                sent_payload_type = type(sent_packet.payload).__name__ \
                    if hasattr(sent_packet, 'payload') and sent_packet.payload else None

                # Handle OACK received → ACK sent (client acknowledges option negotiation)
                if sent_payload_type == 'ACK':
                    self.log.info("  → Client sends ACK to server")

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
                            if 'error' in response:
                                self.log.error(f"  ✗ Error from Docker client: {response['error']}")
                        else:
                            self.log.warning("  No response from Docker client")
                    else:
                        self.log.warning("  Docker manager not initialized, skipping actual operation")
                # Handle ERROR sent (client rejects option negotiation or sends another error)
                elif sent_payload_type == 'ERROR':
                    self.log.info("  → Client sends ERROR to server")

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
                            if 'error' in response:
                                self.log.error(f"  ✗ Error from Docker client: {response['error']}")
                        else:
                            self.log.warning("  No response from Docker client")
                    else:
                        self.log.warning("  Docker manager not initialized, skipping actual operation")
                # Handle RRQ sent (client sends or retransmits read request)
                elif sent_payload_type == 'RRQ':
                    self.log.info("  → Client sends RRQ to server")

                    if self.docker:
                        # Extract packet details
                        src_ip = sent_packet.srcIp
                        src_port = sent_packet.srcPort
                        rrq_payload = sent_packet.payload

                        # Extract RRQ details
                        filename = rrq_payload.filename
                        mode = rrq_payload.mode
                        options = rrq_payload.options

                        # Build RRQ command for Docker client
                        command = {
                            'type': 'rrq',
                            'filename': filename,
                            'mode': mode,
                            'options': dict(options) if hasattr(options, 'items') else {},
                            'source_port': src_port
                        }

                        self.log.info(f"  Sending RRQ command to client: {command}")
                        response = self.docker.send_command_to_client(src_ip, command)

                        if response:
                            if 'error' in response:
                                self.log.error(f"  ✗ Error from Docker client: {response['error']}")
                        else:
                            self.log.warning("  No response from Docker client")
                    else:
                        self.log.warning("  Docker manager not initialized, skipping actual operation")
                else:
                    # TODO: Handle other combinations (DATA→ACK, etc.)
                    self.log.warning(f"  Unhandled send: ... → {sent_payload_type}")
            elif action_tag in ['ActionRecvClose']:
                # This action is handled by the spec and SUT separately
                self.log.info(f"No TFTP operation for {action_tag}")
                pass
            elif action_tag == 'ActionAdvanceClock':
                delta = last_spec_action.delta
                self.log.info(f"Action: Advance Clock by {delta}")
                operation['command'] = 'advance_clock'
                operation['delta'] = delta

                # Sleep for the specified duration to simulate time passing.
                # TODO: It would be nicer to have clock manipulation in the SUT directly.
                time.sleep(delta)
                self.log.info(f"  ✓ Clock advanced by {delta} seconds")
            else:
                self.log.warning(f"Unknown action tag: {action_tag}")
                operation['command'] = 'unknown'

            return operation

        except Exception as e:
            self.log.error(f"Error querying transition details: {e}", exc_info=True)
            return None

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

    def get_run_dir(self, run_number: Optional[int] = None) -> Path:
        """
        Get the directory path for a test run.

        Args:
            run_number: The run number to use. If None, uses self.test_run_number.

        Returns:
            Path to the run directory
        """
        if run_number is None:
            run_number = self.test_run_number
        return self.output_dir / f"run_{run_number:04d}"

    def get_current_trace(self) -> Optional[Tuple[Dict[str, Any], Trace]]:
        """
        Query Apalache for the current trace and decode it.

        Returns:
            Tuple of (trace_json, decoded_trace) or None if query fails
        """
        if not self.client:
            raise RuntimeError("Client not initialized")

        try:
            trace_result = self.client.query(kinds=["TRACE"])
            trace_json = trace_result.get('trace', {})

            # Decode the ITF trace using itf-py
            # The trace follows ITF format (ADR-015): https://apalache-mc.org/docs/adr/015adr-trace.html
            trace = trace_from_json(trace_json)

            return (trace_json, trace)
        except Exception as e:
            self.log.error(f"Error querying trace: {e}", exc_info=True)
            return None

    def get_last_spec_action(self) -> Optional[Any]:
        """
        Get the last action from the current trace.

        Returns:
            The last action from the trace, or None if unavailable
        """
        trace_data = self.get_current_trace()
        if not trace_data:
            return None

        _, trace = trace_data
        self.log.info(f"Retrieved trace with {len(trace.states)} states")

        if not trace.states:
            self.log.warning("Empty trace received")
            return None

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

        return last_action

    def start_apalache(self, hostname: str = "localhost", port: int = 8822):
        """Start the Apalache server using Docker."""
        self.log.info("Starting Apalache server via Docker...")

        # Get the absolute path to the repository root (parent of test-harness)
        repo_root = self.spec_dir.parent.resolve()
        
        # Create directories that Apalache needs with proper permissions
        import os
        tmp_dir = repo_root / "tmp"
        tmp_dir.mkdir(exist_ok=True)
        os.chmod(tmp_dir, 0o777)
        
        apalache_out_dir = repo_root / "_apalache-out"
        apalache_out_dir.mkdir(exist_ok=True)
        os.chmod(apalache_out_dir, 0o777)

        # Docker run command for Apalache server
        docker_cmd = [
            "docker", "run",
            "-d",    # Run in detached mode
            "--name", "apalache-server",  # Named container for easy management
            "-v", f"{repo_root}:/var/apalache",  # Mount repository root
            "-p", f"{port}:{port}",  # Expose port
            "ghcr.io/apalache-mc/apalache:latest",
            "server",
            "--server-type=explorer",
            f"--port={port}"
        ]

        try:
            # Start the Docker container
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                check=True
            )
            container_id = result.stdout.strip()
            self.log.info(f"Apalache server container started: {container_id[:12]}")

            # Store container info for cleanup
            self.server = {
                'container_id': container_id,
                'hostname': hostname,
                'port': port
            }

            # Immediately check if container is running and get logs if not
            time.sleep(1)  # Give it a moment to potentially fail
            
            check_result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", container_id],
                capture_output=True,
                text=True
            )
            
            if check_result.returncode != 0 or check_result.stdout.strip() != "true":
                self.log.error("Apalache container failed to start or exited immediately")
                # Get container logs
                logs_result = subprocess.run(
                    ["docker", "logs", container_id],
                    capture_output=True,
                    text=True
                )
                self.log.error(f"Container logs:\n{logs_result.stdout}\n{logs_result.stderr}")
                # Clean up the stopped container
                subprocess.run(["docker", "rm", container_id], capture_output=True)
                return False

            # Wait for the server to be ready
            self.log.info("Waiting for Apalache server to be ready...")
            max_wait = 30  # Maximum wait time in seconds
            wait_interval = 2
            elapsed = 0

            while elapsed < max_wait:
                time.sleep(wait_interval)
                elapsed += wait_interval

                # Try to check if container is still running
                try:
                    check_result = subprocess.run(
                        ["docker", "inspect", "-f", "{{.State.Running}}", "apalache-server"],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    if check_result.stdout.strip() != "true":
                        self.log.error("Apalache container stopped unexpectedly")
                        # Get container logs to see what went wrong
                        logs_result = subprocess.run(
                            ["docker", "logs", container_id],
                            capture_output=True,
                            text=True
                        )
                        self.log.error(f"Container logs:\n{logs_result.stdout}\n{logs_result.stderr}")
                        return False
                    self.log.info(f"Apalache server still starting... ({elapsed}s)")
                except subprocess.CalledProcessError as e:
                    self.log.error(f"Failed to check Apalache container status: {e.stderr}")
                    # Try to get logs anyway
                    logs_result = subprocess.run(
                        ["docker", "logs", container_id],
                        capture_output=True,
                        text=True
                    )
                    if logs_result.stdout or logs_result.stderr:
                        self.log.error(f"Container logs:\n{logs_result.stdout}\n{logs_result.stderr}")
                    return False

            self.log.info("Apalache server should be ready now")
            return True

        except subprocess.CalledProcessError as e:
            self.log.error(f"Failed to start Apalache server: {e.stderr}")
            return False
        except Exception as e:
            self.log.error(f"Error starting Apalache server: {e}", exc_info=True)
            return False

    def stop_apalache(self):
        """Stop the Apalache Docker container."""
        if self.server:
            self.log.info("Stopping Apalache server...")
            container_id = self.server.get('container_id')
            if container_id:
                try:
                    subprocess.run(
                        ["docker", "stop", container_id],
                        capture_output=True,
                        check=True,
                        timeout=10
                    )
                    self.log.info("Apalache server stopped")
                    # Remove the container
                    subprocess.run(
                        ["docker", "rm", container_id],
                        capture_output=True
                    )
                except subprocess.CalledProcessError as e:
                    self.log.warning(f"Error stopping Apalache server: {e.stderr}")
                except subprocess.TimeoutExpired:
                    self.log.warning("Timeout stopping Apalache server, forcing removal...")
                    try:
                        subprocess.run(
                            ["docker", "rm", "-f", container_id],
                            capture_output=True,
                            check=True
                        )
                    except Exception as e:
                        self.log.error(f"Failed to force remove container: {e}")
                except Exception as e:
                    self.log.error(f"Error stopping Apalache server: {e}")

    def setup_docker(self) -> bool:
        """Set up the Docker environment for TFTP testing."""
        self.log.info("Setting up Docker environment...")

        # Initialize Docker manager
        self.docker = DockerManager(str(self.spec_dir.parent / "test-harness"))

        # Ensure docker_manager logs propagate to root logger and thus to our file handlers
        docker_logger = logging.getLogger('docker_manager')
        docker_logger.propagate = True  # This is True by default, but being explicit

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

    def _spec_packet_from_sut_response(self, response: Dict[str, Any]) -> Any:
        """
        Construct the packet structure from Docker client response
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
                options=ImmutableDict(typed_options)
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

        # Construct packet record
        spec_packet = UdpPacket(
            srcIp=src_ip,
            srcPort=src_port,
            destIp=dest_ip,
            destPort=dest_port,
            payload=payload
        )

        return spec_packet

    def _spec_labels_from_operation(self, spec_packet: UdpPacket) -> List[str]:
        """
        Generate the list of action labels that match the spec-level packet
        from an operation returned by `execute_tftp_operation`.

        Args:
            spec_packet: packet structure as per TLA+ specification from the server
        Returns:
            List of action label strings
        """
        if not hasattr(spec_packet, 'payload'):
            return []

        # For namedtuples, the type name is the tag
        if hasattr(spec_packet.payload, '__class__'):
            tag = type(spec_packet.payload).__name__
        else:
            return []

        if tag == 'DATA':
            return ['ServerRecvRRQthenSendData', 'ServerSendDATA',
                    'ServerResendDATA', 'ServerSendDup', 'ServerSendInvalid']
        elif tag == 'OACK':
            return ['ServerRecvRRQthenSendOack', 'ServerSendDup', 'ServerSendInvalid']
        elif tag == 'ERROR':
            return ['ServerRecvRRQthenSendError', 'ServerSendDup', 'ServerSendError']
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
            return True
        elif isinstance(result, TransitionDisabled):
            return False
        else:
            return False

    def save_test_run(self):
        """Save the current test run to disk."""
        # Note: test_run_number is already incremented and run_dir created in generate_test_run()
        run_dir = self.get_run_dir()

        # Save transitions
        transitions_file = run_dir / "transitions.txt"
        with open(transitions_file, 'w') as f:
            f.write(','.join(map(str, self.transition_log)))

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
                self.sut_command_log,
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

            # Save client logs from all client containers
            for client_ip in DockerManager.CLIENT_IPS:
                client_logs_file = run_dir / f"tftp_client_{client_ip.split('.')[-1]}.log"
                client_logs = self.docker.get_client_logs(client_ip)
                with open(client_logs_file, 'w') as f:
                    f.write(client_logs)
                self.log.info(f"TFTP client logs for {client_ip} saved to {client_logs_file}")

        self.log.info(f"=== Test run {self.test_run_number} completed and saved to {run_dir} ===")

        # Remove the run-specific log handler and close it
        if self.run_log_handlers:
            handler = self.run_log_handlers.pop()
            root_logger = logging.getLogger()
            root_logger.removeHandler(handler)
            handler.close()

        # Reset for next run
        self.transition_log = []
        self.sut_command_log = []


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
    parser.add_argument('--replay', type=str, metavar='TRANSITIONS_FILE',
                        help='Replay transitions from a transitions.txt file')
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

    # Replay mode or normal generation
    if args.replay:
        success = harness.replay_transitions(
            transitions_file=args.replay,
            use_docker=args.docker
        )
    else:
        # Generate test runs
        success = harness.run(num_tests=args.tests, max_steps=args.steps, use_docker=args.docker)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
