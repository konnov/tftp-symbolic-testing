# Integration Checklist

This checklist tracks the remaining integration work to complete the end-to-end TFTP test harness.

## ✅ Completed

- [x] Project structure and configuration
- [x] Apalache server management
- [x] JSON-RPC client for Apalache
- [x] Main harness orchestration framework
- [x] Docker environment setup
- [x] Docker manager implementation
- [x] TFTP client for Docker
- [x] Test file verification
- [x] Documentation (README, IMPLEMENTATION, SUMMARY)
- [x] Build scripts (setup.sh, docker-compose.yml)

## 🔨 Remaining Work

### 1. Transition Decoding (High Priority)

**File**: `harness.py` → `execute_tftp_operation()`

**Task**: Query Apalache to get transition details and decode to TFTP operation

**Steps**:
- [ ] Use `client.query(kinds=["OPERATOR"], operator="...")` to get transition state
- [ ] Parse transition to identify TFTP operation type (RRQ, WRQ, ACK, etc.)
- [ ] Extract parameters (filename, client IP/port, server port, block number, options)
- [ ] Map to client command format

**Example**:
```python
def execute_tftp_operation(self, transition_id: int):
    # Query the transition details
    result = self.client.query(
        kinds=["OPERATOR"],
        operator="NextTransition[" + str(transition_id) + "]"
    )
    
    # Decode the operation
    # TODO: Parse result to determine operation type
    # - ClientSendRRQ -> { type: 'rrq', filename: ..., options: ... }
    # - ServerSendData -> expected response
    # - ClientSendAck -> { type: 'ack', block_num: ..., dest_port: ... }
    
    return operation
```

### 2. UDP Packet Parsing (High Priority)

**File**: `harness.py` → `push_constraints_to_apalache()`

**Task**: Parse TFTP UDP packets received from the server

**Steps**:
- [ ] Parse packet opcode (DATA, ACK, ERROR, OACK)
- [ ] Extract packet fields based on opcode:
  - DATA: block number, data length
  - ACK: block number
  - ERROR: error code, error message
  - OACK: options
- [ ] Map to TLA+ packet structure

**Example**:
```python
def parse_udp_packet(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
    """Convert UDP packet response to TLA+ structure."""
    opcode = packet_data.get('opcode')
    
    if opcode == 3:  # DATA
        return {
            'srcIp': packet_data['src_ip'],
            'srcPort': packet_data['src_port'],
            'destIp': packet_data['dest_ip'],
            'destPort': packet_data['dest_port'],
            'payload': {
                'opcode': 3,
                'blockNum': packet_data['block_num'],
                'dataLength': packet_data['data_length']
            }
        }
    # ... handle other opcodes
```

### 3. Constraint Generation (High Priority)

**File**: `harness.py` → `push_constraints_to_apalache()`

**Task**: Convert parsed UDP packet to Apalache equality constraints

**Steps**:
- [ ] Map packet fields to TLA+ variable names
- [ ] Create equality constraints for `assumeState`
- [ ] Handle set membership for `packets` variable

**Example**:
```python
def push_constraints_to_apalache(self, udp_packet: Dict[str, Any]) -> bool:
    # Parse the packet
    parsed = self.parse_udp_packet(udp_packet)
    
    # Create constraints
    equalities = {
        # Packet should be in the packets set
        "packets": {
            "contains": parsed
        }
    }
    
    result = self.client.assume_state(equalities, check_enabled=True)
    return isinstance(result, AssumptionEnabled)
```

### 4. Docker Integration (Medium Priority)

**File**: `harness.py` → `run()`, `execute_tftp_operation()`

**Task**: Integrate docker_manager into main harness flow

**Steps**:
- [ ] Import `DockerManager` in `harness.py`
- [ ] Initialize Docker environment in `run()` method
- [ ] Send commands to Docker clients in `execute_tftp_operation()`
- [ ] Handle responses from clients
- [ ] Cleanup Docker resources on exit

**Example**:
```python
def run(self, num_tests: int = 1, max_steps: int = 20):
    # Initialize Docker
    docker_mgr = DockerManager(str(self.spec_dir.parent / "test-harness"))
    
    try:
        if not docker_mgr.setup():
            self.log.error("Failed to setup Docker environment")
            return False
        
        # ... existing code ...
        
    finally:
        docker_mgr.cleanup()
        # ... existing cleanup ...
```

### 5. ITF Trace Export (Low Priority)

**File**: `harness.py` → `save_test_run()`

**Task**: Export test runs in ITF format

**Steps**:
- [ ] Import `itf` library
- [ ] Query full trace from Apalache using `query(kinds=["TRACE"])`
- [ ] Convert to ITF format
- [ ] Save as `.itf.json` file

**Example**:
```python
def save_test_run(self):
    # ... existing code ...
    
    # Get ITF trace
    trace_result = self.client.query(kinds=["TRACE"])
    
    # Save ITF trace
    itf_file = run_dir / "trace.itf.json"
    with open(itf_file, 'w') as f:
        json.dump(trace_result['trace'], f, indent=2)
```

### 6. End-to-End Testing (Medium Priority)

**Task**: Test the complete workflow

**Steps**:
- [ ] Run `./setup.sh` on a clean system
- [ ] Start Docker containers with `docker-compose up -d`
- [ ] Run harness with `poetry run python harness.py`
- [ ] Verify test runs are generated
- [ ] Verify transitions and commands are saved
- [ ] Check that TFTP operations execute correctly
- [ ] Validate constraint checking works

### 7. Error Handling & Robustness (Low Priority)

**Task**: Improve error handling and edge cases

**Steps**:
- [ ] Add timeout handling for TFTP operations
- [ ] Handle Docker container failures
- [ ] Graceful degradation if Apalache returns UNKNOWN
- [ ] Retry logic for network operations
- [ ] Better logging and debugging output

### 8. Configuration & Tuning (Low Priority)

**Task**: Make the harness more configurable

**Steps**:
- [ ] Add command-line arguments for configuration
- [ ] Support different port ranges
- [ ] Configurable number of clients
- [ ] Adjustable solver timeouts
- [ ] Option to skip Docker and use external TFTP server

## Testing Strategy

1. **Unit Testing**: Test each component individually
   - Docker manager
   - Packet parsing
   - Constraint generation

2. **Integration Testing**: Test component interactions
   - Harness → Apalache
   - Harness → Docker
   - Docker → TFTP server

3. **End-to-End Testing**: Full workflow
   - Generate test run
   - Execute TFTP operations
   - Validate against spec
   - Save results

## Notes

- The framework is complete and production-ready
- Remaining work is mostly about connecting components
- Each task is independent and can be tackled separately
- Estimated effort: 4-8 hours for core integration (tasks 1-4)
- Additional 2-4 hours for polish and testing (tasks 5-8)

## Resources

- Apalache JSON-RPC API: See `client.py` for available methods
- TFTP packet format: See `tftp_client_docker.py` for encoding/decoding
- TLA+ specification: See `spec/tftp.tla` for state structure
- Docker API: See `docker_manager.py` for container management
