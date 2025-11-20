# TFTP Test Harness

A symbolic test harness for the TFTP protocol using the [Apalache model checker][Apalache].

This harness generates concrete test cases by exploring symbolic executions of the TLA+ specification using Apalache's JSON-RPC API.

[Apalache]: https://apalache-mc.org/

## Overview

This test harness systematically tests TFTP protocol implementations by:

1. Starting Apalache server in Docker
2. Loading the TLA+ specification of TFTP from [`../spec/`](../spec)
3. Exploring symbolic executions via Apalache's JSON-RPC API
4. Optionally executing actual TFTP operations in Docker containers
5. Validating server responses against the specification
6. Detecting divergences when implementation behavior differs from the spec

## Architecture

### Components

- **[`harness.py`](./harness.py)**: Main orchestrator coordinating symbolic execution and test generation
- **[`docker_manager.py`](./docker_manager.py)**: Docker orchestration for TFTP server (tftp-hpa) and clients
- **[`tftp_client_docker.py`](./tftp_client_docker.py)**: TFTP client running inside Docker containers
- **[`Dockerfile`](./Dockerfile)**: Docker image with tftp-hpa server and Python client
- **[`pyproject.toml`](./pyproject.toml)**: Poetry configuration with dependencies

### Network Configuration

As specified in [`MC2_tftp.tla`](../spec/MC2_tftp.tla):

- **Server IP**: `172.20.0.10`
- **Client IPs**: `172.20.0.11`, `172.20.0.12`
- **TFTP Control Port**: 69
- **TFTP Data Ports**: 1024-1027
- **Client Control Port**: 5000 (TCP, for receiving commands from harness)

### Test Files

The test files are specified in [`MC2_tftp.tla`](../spec/MC2_tftp.tla):

- `file1` (1024 bytes)
- `file2` (2099 bytes)
- `file3` (12345 bytes)

## Requirements

### System Requirements

- **Python**: 3.9 or higher
- **Docker**: 20.10 or higher (for Apalache server and TFTP testing)
- **Memory**: 4GB RAM minimum (8GB recommended)

### Python Dependencies

Core dependencies (managed by Poetry):

- `requests` - HTTP client for JSON-RPC
- `itf-py` - ITF trace format support
- `apalache-rpc-client` - Apalache JSON-RPC client
- `orjson` - Fast JSON serialization
- `frozendict` - Immutable dictionaries

## Setup

1. **Install Apalache via Docker**:
   ```bash
   docker pull ghcr.io/apalache-mc/apalache
   ```

2. **Install Python Dependencies**:
   ```bash
   poetry install
   ```

3. **Build TFTP Docker Image** (only if using `--docker` flag):
   ```bash
   docker build -t tftp-test-harness:latest .
   ```

## Usage

### Basic Test Generation (Symbolic Only)

Generate test cases without running actual TFTP operations:

```bash
python harness.py --tests 10 --steps 100
```

**Arguments:**
- `--tests N`: Number of test runs to generate (default: 10)
- `--steps N`: Maximum steps per test run (default: 100)
- `--docker`: Enable Docker to run actual TFTP operations (optional)

### Running with Docker (Full Integration)

Execute actual TFTP operations against tftp-hpa server:

```bash
python harness.py --tests 10 --steps 100 --docker
```

This will:
1. Start Apalache server in Docker
2. Load the TFTP specification
3. Build and start TFTP server and client containers
4. Generate symbolic test runs and execute them
5. Validate responses against specification
6. Save results to `test-results/`

### Test Output

Each test run creates `test-results/run_NNNN/` containing:

- `python_harness.log`: Complete execution log with timestamps
- `transitions.txt`: Sequence of transition indices taken
- `commands.json`: TFTP operations executed with responses
- `divergence_trace.itf.json`: ITF trace when test diverges from spec (if applicable)
- `tftpd_server.log`: TFTP server container logs (with `--docker`)
- `tftpd_syslog.log`: Server syslog output (with `--docker`)

## How It Works

### Test Generation Algorithm

For each test run, the harness:

1. **Initialization**: 
   - Loads specification into Apalache
   - Creates initial snapshot

2. **Exploration Loop**:
   - Query available transitions from Apalache
   - Randomly select an enabled transition
   - Try to assume it via `assumeTransition`
   - If enabled:
     - Decode the action from `lastAction` variable
     - Send corresponding TFTP command to client (via Docker, if `--docker` enabled)
     - Collect UDP response from server
     - Validate response matches specification expectations
     - If mismatch detected: save divergence trace and exit
     - Otherwise: move to next step via `nextStep`
   - If disabled: rollback to previous snapshot and try another transition
   - Repeat until max steps reached or no transitions available

3. **Test Saving**:
   - Save sequence of transitions to `transitions.txt`
   - Save commands and responses to `commands.json`
   - Save divergence trace (if test diverged from spec)

### Docker Integration

When running with `--docker` flag, the harness manages:

- **TFTP Server**: tftp-hpa running in Docker at `172.20.0.10`
- **TFTP Clients**: Python scripts listening on TCP port 5000
- **Communication**: Harness sends commands via TCP, clients execute TFTP ops via UDP

### Symbolic Execution

- Uses Apalache's explorer mode via JSON-RPC
- Explores state space by assuming transitions
- Validates concrete executions against symbolic constraints
- Detects violations when implementation diverges from specification

## Implementation Status

### Fully Implemented

- ✅ Apalache server management via Docker
- ✅ JSON-RPC client for Apalache API (`apalache-rpc-client`)
- ✅ Test harness orchestration framework
- ✅ Docker environment for TFTP server and clients
- ✅ TFTP client implementation for Docker
- ✅ Action decoding and TFTP command generation
- ✅ UDP packet parsing and validation
- ✅ Test divergence detection and ITF trace generation
- ✅ Per-run logging and result saving
- ✅ Support for RRQ, ACK, ERROR operations
- ✅ Timeout and crash handling
- ✅ Clock advancement

## Troubleshooting

### Apalache Server Won't Start

- Verify Docker image is pulled: `docker images | grep apalache`
- Check Docker daemon is running: `docker ps`
- Check container logs: `docker logs apalache-server`
- Ensure port 8822 is available: `lsof -i :8822`

### Docker Containers Not Starting

- Check Docker daemon is running: `docker ps`
- Verify network creation: `docker network ls | grep tftp`
- Check container logs: `docker logs tftp-server`
- Rebuild image: `docker build -t tftp-test-harness:latest .`

### Port Conflicts

- TFTP uses UDP port 69 (may require elevated privileges on some systems)
- Client control uses TCP port 5000
- Apalache uses TCP port 8822
- Check ports are available: `lsof -i :69 -i :5000 -i :8822`

## Visualization

See [`../scripts/`](../scripts) for visualization tools:

- **[`log_to_mermaid.py`](../scripts/log_to_mermaid.py)**: Convert test logs to Mermaid sequence diagrams
- **[`itf_to_mermaid.py`](../scripts/itf_to_mermaid.py)**: Convert ITF traces to Mermaid diagrams
- **[`log_to_plot.py`](../scripts/log_to_plot.py)**: Timing analysis with stacked bar charts

## References

- [Apalache Model Checker](https://apalache-mc.org/)
- [ITF Format Specification](https://apalache-mc.org/docs/adr/015adr-trace.html)
- [TFTP RFC 1350](https://datatracker.ietf.org/doc/html/rfc1350) (Basic protocol)
- [TFTP Options RFCs 2347-2349](https://datatracker.ietf.org/doc/html/rfc2347) (Option negotiation)
