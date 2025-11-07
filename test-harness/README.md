# TFTP Test Harness

A symbolic test harness for the TFTP protocol using Apalache model checker.

## Overview

This test harness generates test cases for TFTP protocol implementations by:
1. Loading the TLA+ specification of TFTP
2. Exploring symbolic executions using Apalache's JSON-RPC API
3. Running actual TFTP operations in Docker containers
4. Validating server responses against the specification

## Architecture

### Components

- **`harness.py`**: Main orchestrator that coordinates symbolic execution and test generation
- **`client.py`**: JSON-RPC client for communicating with Apalache
- **`server.py`**: Apalache server management
- **`docker_manager.py`**: Docker orchestration for TFTP server and clients
- **`tftp_client_docker.py`**: TFTP client that runs in Docker and executes operations
- **`Dockerfile`**: Docker image containing tftp-hpa server and Python client

### Network Configuration

As specified in `MC2_tftp.tla`:
- **Server IP**: 172.20.0.10
- **Client IPs**: 172.20.0.11, 172.20.0.12
- **TFTP Control Port**: 69
- **TFTP Data Ports**: 1024-1027
- **Client Control Port**: 5000 (TCP, for receiving commands from harness)

### Files

The test files are specified in `MC2_tftp.tla`:
- `file1` (1024 bytes)
- `file2` (2099 bytes)
- `file3` (12345 bytes)

## Requirements

### System Requirements

- Python 3.9+
- Docker
- Apalache model checker (must be in PATH or APALACHE_HOME set)

### Python Dependencies

Install using Poetry:

```bash
cd test-harness
poetry install
```

Or with pip:

```bash
pip install requests itf
```

## Setup

1. **Install Apalache**: Ensure `apalache-mc` is available in your PATH or set `APALACHE_HOME`

2. **Install Dependencies**:
   ```bash
   cd test-harness
   poetry install
   ```

3. **Build Docker Image**:
   ```bash
   cd test-harness
   docker build -t tftp-test-harness:latest .
   ```

## Usage

### Basic Test Generation

Run the harness to generate test cases:

```bash
cd test-harness
poetry run python harness.py
```

This will:
1. Start Apalache server
2. Load the TFTP specification
3. Generate symbolic test runs
4. Save results to `test-results/`

### Configuration

Edit `harness.py` to configure:
- Number of test runs: `harness.run(num_tests=3, max_steps=10)`
- Solver timeout: Modify `solver_timeout` in `load_specification()`
- Output directory: Change `output_dir` in `main()`

### Test Output

Each test run is saved to `test-results/run_NNNN/`:
- `transitions.txt`: Comma-separated list of transition IDs
- `commands.json`: Sequence of TFTP operations and responses

## How It Works

### Test Generation Algorithm (Requirement 11)

For each test run:

1. **Initialization**: 
   - Select a random init transition from `loadSpec` results
   - Assume it via `assumeTransition`

2. **Exploration Loop**:
   - Randomly select a next transition
   - Assume it via `assumeTransition`
   - If disabled, rollback and try another transition
   - If enabled:
     - Send corresponding TFTP command to client (via Docker)
     - Collect UDP response from server
     - Push response constraints to Apalache via `assumeState`
     - If `assumeState` returns DISABLED: save test run and exit
     - Otherwise: move to next step

3. **Test Saving**:
   - Save sequence of transitions to `transitions.txt`
   - Save commands and responses to `commands.json`

### Docker Integration

The harness manages:
- **TFTP Server**: tftp-hpa running in Docker at 172.20.0.10
- **TFTP Clients**: Python scripts listening on TCP port 5000
- **Communication**: Harness sends commands via TCP, clients execute TFTP ops via UDP

### Symbolic Execution

- Uses Apalache's explorer mode via JSON-RPC
- Explores state space by assuming transitions
- Validates concrete executions against symbolic constraints
- Detects violations when `assumeState` returns DISABLED

## Development Status

### Implemented

- ✅ Apalache server management
- ✅ JSON-RPC client for Apalache API
- ✅ Test harness orchestration framework
- ✅ Docker environment setup
- ✅ TFTP client for Docker
- ✅ Project structure and dependencies

### TODO

- ⚠️ Query Apalache for transition details (to decode TFTP operations)
- ⚠️ Convert transition to TFTP commands
- ⚠️ Parse UDP packets and extract constraints
- ⚠️ Convert UDP packet to Apalache equality constraints
- ⚠️ Integrate Docker manager with main harness
- ⚠️ End-to-end testing
- ⚠️ ITF trace generation/parsing

## Troubleshooting

### Apalache Server Won't Start

- Check that `apalache-mc` is in your PATH: `which apalache-mc`
- Or set APALACHE_HOME: `export APALACHE_HOME=/path/to/apalache`
- Check logs in `test-harness/logs/apalache_8822.out`

### Docker Containers Not Starting

- Check Docker daemon is running: `docker ps`
- Verify network creation: `docker network ls | grep tftp`
- Check container logs: `docker logs tftp-server`

### Port Conflicts

- TFTP uses UDP port 69 (requires root/sudo in some systems)
- Client control uses TCP port 5000
- Check ports are available: `netstat -an | grep 69`

## References

- [Apalache Model Checker](https://github.com/informalsystems/apalache)
- [ITF Format Specification](https://apalache-mc.org/docs/adr/015adr-trace.html)
- [TFTP RFC 1350](https://www.rfc-editor.org/rfc/rfc1350)
- [TFTP Options RFC 2347-2349](https://www.rfc-editor.org/rfc/rfc2347)
