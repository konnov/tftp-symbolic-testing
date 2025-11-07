#!/usr/bin/env python3
"""
TFTP Test Harness - Main orchestrator for symbolic testing of TFTP protocol.

This script:
1. Starts the Apalache server
2. Loads the TFTP specification
3. Generates test runs by exploring symbolic executions
4. Controls Docker containers running the TFTP server and clients
5. Executes TFTP operations and validates against the specification

Igor Konnov, 2025
"""

import json
import logging
import os
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from itf_py import Trace, trace_from_json

from client import (
    JsonRpcClient,
    AssumptionDisabled,
    AssumptionEnabled,
    TransitionEnabled,
    TransitionDisabled,
)
from server import ApalacheServer


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
        self.log.info(f"Init transitions: {len(self.spec_params['init'])}")
        self.log.info(f"Next transitions: {len(self.spec_params['next'])}")

        return True

    def select_random_transition(self, transitions: List[Any]) -> int:
        """
        Randomly select a transition from the available transitions.

        Args:
            transitions: List of transition objects with 'index' and 'labels'

        Returns:
            The index of the selected transition
        """
        transition = random.choice(transitions)
        # Transitions are objects like {'index': 0, 'labels': [...]}
        if isinstance(transition, dict) and 'index' in transition:
            return int(transition['index'])
        # Fallback if it's already an integer
        if isinstance(transition, int):
            return transition
        # Should not happen, but raise an error if it does
        raise ValueError(f"Unexpected transition format: {transition}")

    def try_transition(self, transition_id: int) -> bool:
        """
        Try to assume a transition and check if it's enabled.

        Args:
            transition_id: The ID of the transition to try

        Returns:
            True if the transition is enabled, False otherwise
        """
        if not self.client:
            raise RuntimeError("Client not initialized")

        self.log.info(f"Trying transition {transition_id}...")

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

            # Try to decode the ITF trace using itf-py
            # The trace follows ITF format (ADR-015): https://apalache-mc.org/docs/adr/015adr-trace.html
            try:
                trace = trace_from_json(trace_json)
                states = trace.states
                self.log.info(f"Retrieved trace with {len(states)} states (decoded with itf-py)")
                use_itf = True
            except (AttributeError, KeyError) as e:
                # itf-py may fail on certain variant types (e.g., unit types)
                # Fall back to manual JSON parsing
                self.log.warning(f"itf-py decoding failed: {e}, falling back to manual JSON parsing")
                states = trace_json.get('states', [])
                self.log.info(f"Retrieved trace with {len(states)} states (manual JSON)")
                use_itf = False

            if states:
                # Get the last state in the trace
                if use_itf:
                    # itf-py decoded State object
                    itf_state = states[-1]
                    state_index = itf_state.meta.get('index', '?')
                    state_values = itf_state.values
                else:
                    # Raw JSON dict
                    json_state = states[-1]
                    state_index = json_state.get('#meta', {}).get('index', '?')  # type: ignore
                    state_values = {k: v for k, v in json_state.items() if k != '#meta'}  # type: ignore

                self.log.info(f"Current state index: {state_index}")

                # state_values should be a dictionary
                if not isinstance(state_values, dict):
                    self.log.error(f"Unexpected state values type: {type(state_values)}, value: {state_values}")
                    return None

                self.log.info(f"Current state keys: {state_values.keys()}")

                # Extract lastAction from the state
                last_action = state_values.get('lastAction')
                if last_action is None:
                    self.log.warning("No lastAction in current state")
                    return None

                # For manual JSON, lastAction is a dict with 'tag' and 'value'
                # For itf-py, it would be a namedtuple, but we're using manual JSON for now
                if isinstance(last_action, dict):
                    action_tag = last_action.get('tag', 'Unknown')
                    action_value = last_action.get('value', {})
                else:
                    # itf-py decoded variant
                    action_tag = last_action.tag
                    action_value = last_action.value

                self.log.info(f"lastAction tag: {action_tag}")
                self.log.info(f"lastAction value type: {type(action_value)}")

                # Determine the TFTP operation based on the action tag
                operation = {
                    'transition_id': transition_id,
                    'timestamp': time.time(),
                    'action_tag': action_tag,
                    'action_value': action_value,
                }

                # Parse the action to determine what TFTP command to send
                if action_tag == 'ActionInit':
                    self.log.info("Action: Initialization")
                    operation['command'] = 'init'

                elif action_tag == 'ActionClientSendRRQ':
                    self.log.info("Action: Client sends RRQ")
                    # action_value should be a dict with 'sent' key
                    sent_packet = action_value.get('sent') if isinstance(action_value, dict) else action_value.sent
                    operation['command'] = 'send_rrq'
                    operation['packet'] = sent_packet
                    # TODO: Send RRQ command to Docker client

                elif action_tag == 'ActionRecvSend':
                    # action_value should have 'rcvd' and 'sent' fields
                    rcvd_packet = action_value.get('rcvd') if isinstance(action_value, dict) else action_value.rcvd
                    sent_packet = action_value.get('sent') if isinstance(action_value, dict) else action_value.sent
                    self.log.info(f"Action: Receive and Send")
                    self.log.info(f"  Received packet type: {type(rcvd_packet)}")
                    self.log.info(f"  Sent packet type: {type(sent_packet)}")
                    operation['command'] = 'recv_send'
                    operation['rcvd_packet'] = rcvd_packet
                    operation['sent_packet'] = sent_packet
                    # TODO: Send appropriate command to Docker client based on packet types

                elif action_tag == 'ActionRecvClose':
                    rcvd_packet = action_value.get('rcvd') if isinstance(action_value, dict) else action_value.rcvd
                    self.log.info(f"Action: Receive and Close")
                    self.log.info(f"  Received packet type: {type(rcvd_packet)}")
                    operation['command'] = 'recv_close'
                    operation['rcvd_packet'] = rcvd_packet
                    # TODO: Close the connection

                elif action_tag == 'ActionClientTimeout':
                    ip_port = action_value.get('ipPort') if isinstance(action_value, dict) else action_value.ipPort
                    self.log.info(f"Action: Client Timeout on {ip_port}")
                    operation['command'] = 'client_timeout'
                    operation['ip_port'] = ip_port
                    # TODO: Handle client timeout

                elif action_tag == 'ActionServerTimeout':
                    ip_port = action_value.get('ipPort') if isinstance(action_value, dict) else action_value.ipPort
                    self.log.info(f"Action: Server Timeout on {ip_port}")
                    operation['command'] = 'server_timeout'
                    operation['ip_port'] = ip_port
                    # TODO: Handle server timeout

                elif action_tag == 'ActionAdvanceClock':
                    delta = action_value.get('delta') if isinstance(action_value, dict) else action_value.delta
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

    def generate_test_run(self, max_steps: int = 20, max_retries: int = 10) -> bool:
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
        init_transitions = self.spec_params['init']
        if not init_transitions:
            self.log.error("No init transitions available")
            return False

        init_trans = self.select_random_transition(init_transitions)
        self.log.info(f"Selected init transition: {init_trans}")

        if not self.try_transition(init_trans):
            self.log.error("Init transition is not enabled")
            return False

        self.current_transitions.append(init_trans)

        # Move to next step
        self.current_snapshot = self.client.next_step()

        # Main exploration loop
        next_transitions = self.spec_params['next']

        for step in range(max_steps):
            self.log.info(f"\n--- Step {step + 1}/{max_steps} ---")

            enabled_found = False

            # Try to find an enabled transition
            for retry in range(max_retries):
                # Select a random next transition
                next_trans = self.select_random_transition(next_transitions)

                # Save current snapshot before trying
                snapshot_before = self.current_snapshot

                # Try the transition
                if self.try_transition(next_trans):
                    enabled_found = True
                    self.current_transitions.append(next_trans)

                    # Execute the corresponding TFTP operation
                    operation = self.execute_tftp_operation(next_trans)
                    if operation:
                        self.current_commands.append(operation)

                    # Move to next step
                    self.current_snapshot = self.client.next_step()

                    # TODO: In a real implementation, push constraints from
                    # the UDP response and check if they're satisfied
                    # For now, we continue until max_steps

                    break
                else:
                    # Transition was disabled, rollback and try another
                    if snapshot_before is not None:
                        self.log.info(f"Rollback to snapshot {snapshot_before}")
                        self.client.rollback(snapshot_before)
                        self.current_snapshot = snapshot_before

            if not enabled_found:
                self.log.warning(f"Could not find enabled transition after {max_retries} retries")
                break

        # Save the test run
        self.save_test_run()

        return True

    def run(self, num_tests: int = 1, max_steps: int = 20):
        """
        Main entry point for the test harness.

        Args:
            num_tests: Number of test runs to generate
            max_steps: Maximum steps per test run
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
            if self.client:
                self.client.dispose_spec()
                self.client.close()

            self.stop_apalache()


def main():
    """Main entry point."""
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
    success = harness.run(num_tests=3, max_steps=10)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
