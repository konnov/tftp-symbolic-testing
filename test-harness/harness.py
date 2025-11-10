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

from copy import deepcopy
import json
import logging
import os
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from itf_py import Trace, trace_from_json, value_to_json

from client import (
    JsonRpcClient,
    AssumptionDisabled,
    AssumptionEnabled,
    TransitionEnabled,
    TransitionDisabled,
)
from docker_manager import DockerManager
from server import ApalacheServer

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
        self.current_commands = []

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

    def _construct_expected_packet(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Construct an expected packet structure from Docker client response
        that matches the TLA+ specification format.

        Args:
            response: Response from Docker client containing packet details

        Returns:
            Expected packet dictionary in TLA+ format
        """
        # Extract packet details from response
        opcode = response.get('opcode')
        src_ip = response.get('src_ip')
        src_port = response.get('src_port')
        dest_ip = response.get('dest_ip')
        dest_port = response.get('dest_port')

        # Construct base packet structure matching TLA+ $udpPacket type
        expected = {
            'srcIp': src_ip,
            'srcPort': src_port,
            'destIp': dest_ip,
            'destPort': dest_port,
        }

        # Add payload based on opcode
        # Payload structure matches TLA+ Variant type: {tag: "...", value: {...}}
        if opcode == 6:  # OACK
            options = response.get('options', {})
            # Convert string values to integers where applicable
            typed_options = {}
            for key, value in options.items():
                try:
                    typed_options[key] = int(value)
                except (ValueError, TypeError):
                    typed_options[key] = value

            expected['payload'] = {
                'tag': 'OACK',
                'value': {
                    'opcode': 6,
                    'options': typed_options
                }
            }
        elif opcode == 3:  # DATA
            block_num = response.get('block_num')
            data = response.get('data', 0)  # size or actual data
            expected['payload'] = {
                'tag': 'DATA',
                'value': {
                    'opcode': 3,
                    'blockNum': block_num,
                    'data': data
                }
            }
        elif opcode == 4:  # ACK
            block_num = response.get('block_num')
            expected['payload'] = {
                'tag': 'ACK',
                'value': {
                    'opcode': 4,
                    'blockNum': block_num
                }
            }
        elif opcode == 5:  # ERROR
            error_code = response.get('error_code')
            error_msg = response.get('error_msg', '')
            expected['payload'] = {
                'tag': 'ERROR',
                'value': {
                    'opcode': 5,
                    'errorCode': error_code,
                    'errorMsg': error_msg
                }
            }

        return expected

    def _labels_from_operation(self, operation: Dict[str, Any]) -> List[str]:
        """
        Generate the list of action labels that match the expected packet
        from an operation returned by `execute_tftp_operation`.

        Args:
            operation: Operation dictionary from execute_tftp_operation
        Returns:
            List of action label strings
        """
        # Check if operation has an expected_packet
        if not operation or 'packet_from_server' not in operation:
            return []
        
        packet = operation['packet_from_server']
        payload = packet.get('payload', {})
        
        # Check if payload has a tag
        if not payload or 'tag' not in payload:
            return []
        
        tag = payload['tag']
        
        if tag == 'DATA':
            return ['ServerRecvRRQthenSendData', 'ServerSendDATA']
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

    def try_transition(self, transition: Dict['str', Any]) -> bool:
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

    def execute_tftp_operation(self, transition_id: int) -> Optional[Dict[str, Any]]:
        """
        Execute the TFTP operation corresponding to the transition.

        This is a placeholder that would need to:
        1. Decode the transition to determine the TFTP operation
        2. Send commands to the Docker client
        3. Collect the response from the TFTP server

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

                self.log.info(f"Current state index: {state_index}")
                self.log.info(f"Current state keys: {state_values.keys()}")

                # Extract lastAction from the state
                last_action = state_values.get('lastAction')
                if last_action is None:
                    self.log.warning("No lastAction in current state")
                    return None

                # With itf-py 0.4.1+, variants are decoded as typed namedtuples
                # The type name is the tag (e.g., 'ActionInit', 'ActionClientSendRRQ')
                action_tag = type(last_action).__name__
                self.log.info(f"lastAction type: {action_tag}")
                self.log.info(f"lastAction fields: {last_action._fields if hasattr(last_action, '_fields') else 'N/A'}")

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
                    operation['packet'] = sent_packet

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
                            if 'opcode' in response and 'error' not in response:
                                expected_packet = self._construct_expected_packet(response)
                                operation['packet_from_server'] = expected_packet
                                operation['packet_to_server'] = sent_packet
                                self.log.info(f"Expected packet for validation: {expected_packet}")
                        else:
                            self.log.warning("No response from Docker client")
                    else:
                        self.log.warning("Docker manager not initialized, skipping actual TFTP operation")

                elif action_tag == 'ActionRecvSend':
                    rcvd_packet = last_action.rcvd
                    sent_packet = last_action.sent
                    self.log.info(f"Action: Receive and Send")
                    self.log.info(f"  Received packet type: {type(rcvd_packet)}")
                    self.log.info(f"  Sent packet type: {type(sent_packet)}")
                    operation['command'] = 'recv_send'
                    operation['rcvd_packet'] = rcvd_packet
                    operation['sent_packet'] = sent_packet
                    # TODO: Send appropriate command to Docker client based on packet types

                elif action_tag == 'ActionRecvClose':
                    rcvd_packet = last_action.rcvd
                    self.log.info(f"Action: Receive and Close")
                    self.log.info(f"  Received packet type: {type(rcvd_packet)}")
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
                    # TODO: Sleep or advance time in the test environment

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

    def push_constraints_to_apalache(self, udp_packet: Dict[str, Any]) -> bool:
        """
        Push constraints from the UDP packet to Apalache via assumeState.

        Args:
            udp_packet: The UDP packet received from the TFTP server

        Returns:
            True if constraints are satisfied (ENABLED), False if DISABLED
        """
        if not self.client:
            raise RuntimeError("Client not initialized")

        self.log.info("Pushing UDP packet constraints to Apalache...")

        # TODO: Convert UDP packet to equality constraints
        # This needs to extract fields from the packet and create
        # equalities that match the TLA+ specification format

        equalities = {}  # Placeholder

        result = self.client.assume_state(equalities, check_enabled=True)

        if isinstance(result, AssumptionEnabled):
            self.log.info("Constraints are satisfied (ENABLED)")
            return True
        elif isinstance(result, AssumptionDisabled):
            self.log.info("Constraints violated (DISABLED)")
            return False
        else:
            self.log.warning("Constraint status is UNKNOWN")
            return False

    def save_test_run(self):
        """Save the current test run to disk."""
        self.test_run_number += 1
        run_dir = self.output_dir / f"run_{self.test_run_number:04d}"
        run_dir.mkdir(parents=True, exist_ok=True)

        # Save transitions
        transitions_file = run_dir / "transitions.txt"
        with open(transitions_file, 'w') as f:
            f.write(','.join(map(str, self.current_transitions)))

        # Save commands and responses
        commands_file = run_dir / "commands.json"
        with open(commands_file, 'w') as f:
            json.dump(self.current_commands, f, indent=2)

        self.log.info(f"Test run {self.test_run_number} saved to {run_dir}")

        # Reset for next run
        self.current_transitions = []
        self.current_commands = []

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

        self.log.info(f"=== Starting test run generation (max {max_steps} steps) ===")

        # Initialize with a random init transition
        # TODO: In this case, there is only one init transition,
        # in other projects there may be more
        init_transitions = self.spec_params['init']
        if not init_transitions:
            self.log.error("No init transitions available")
            return False

        init_trans = random.choice(init_transitions)
        self.log.info(f"Selected init transition: {init_trans}")

        if not self.try_transition(init_trans):
            self.log.error("Init transition is not enabled")
            return False

        self.current_transitions.append(init_trans)

        # Move to next step
        self.current_snapshot = self.client.next_step()

        # Main exploration loop
        next_transitions = self.spec_params['next']

        turn = TESTER   # Track whose turn it is: tester or SUT
        operation = None   # the last operation executed (from tester side)
        for step in range(max_steps):
            self.log.info(f"\n--- Step {step + 1}/{max_steps} ---")

            enabled_found = False

            # Try to find an enabled transition by the player whose turn it is.
            # Only use the transitions that match the current turn.
            if turn == TESTER:
                transitions_to_try = [ trans for trans in next_transitions \
                    if frozenset(trans.get("labels")).intersection(TESTER_ACTION_LABELS)
                ]
            else:
                op_labels = self._labels_from_operation(operation) if operation else []
                print(f"Operation labels for SUT turn: {op_labels}")
                transitions_to_try = [ trans for trans in next_transitions \
                    if any(label in op_labels for label in trans.get("labels", []))
                ]

            while len(transitions_to_try) > 0 and not enabled_found:
                # Select a random next transition from the transitions we have not tried yet
                next_trans = random.choice(transitions_to_try)
                transitions_to_try.remove(next_trans)

                # Save current snapshot before trying
                snapshot_before = self.current_snapshot

                # Try the transition in Apalache
                if not self.try_transition(next_trans):
                    # Transition was disabled, rollback and try another
                    if snapshot_before is not None:
                        self.log.info(f"Rollback to snapshot {snapshot_before}")
                        self.client.rollback(snapshot_before)
                        self.current_snapshot = snapshot_before
                else:
                    enabled_found = True
                    self.current_transitions.append(next_trans)

                    # Move to next step in Apalache
                    self.current_snapshot = self.client.next_step()

                    if turn == TESTER:
                        # Execute the corresponding TFTP operation
                        operation = self.execute_tftp_operation(next_trans["index"])
                        if operation:
                            # TODO: called it a log?
                            self.current_commands.append(operation)

                            if 'packet_from_server' in operation:
                                # We have received feedback from the SUT.
                                # Plan its evaluation for the next iteration.
                                turn = SUT
                    else:
                        if not operation:
                            self.log.error("No operation to validate on SUT turn")
                            return False

                        expected_last_action = {
                            'tag': 'ActionRecvSend',
                            'value': {
                                'rcvd': operation['packet_to_server'],
                                'sent': operation['packet_from_server'],
                            }
                        }
                        self.log.info(f"Assume lastAction: {expected_last_action}")
                        # Assume that lastAction equals the reconstructed action
                        equalities = {
                            "lastAction": value_to_json(expected_last_action)
                        }
                        assume_result = self.client.assume_state(equalities, check_enabled=True)
                        if isinstance(assume_result, AssumptionEnabled):
                            self.log.info("✓ Received packet matches symbolic execution")
                            turn = TESTER
                            operation = None
                        elif isinstance(assume_result, AssumptionDisabled):
                            self.log.warning("✗ Received packet does NOT match symbolic execution - test diverged!")
                            # Test found a discrepancy - this is valuable!
                            # Continue to save at the end of the run
                        else:
                            self.log.warning("? Unable to validate received packet")

            if not enabled_found:
                self.log.warning(f"✗ Could not find enabled transition for turn '{turn}' - ending test run")
                break

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
    parser.add_argument('--tests', type=int, default=3,
                        help='Number of test runs to generate (default: 3)')
    parser.add_argument('--steps', type=int, default=10,
                        help='Maximum steps per test run (default: 10)')
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
