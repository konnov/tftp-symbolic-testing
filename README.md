# Symbolic Testing of TFTP with Apalache

This repository demonstrates **symbolic testing** of the [Trivial File Transfer
Protocol][TFTP] (TFTP) using the [Apalache model checker][Apalache]. The
approach combines formal specification in TLA<sup>+</sup> with automated test
generation to systematically explore protocol behaviors and validate
implementations.

This repository accompanies my talk at Nvidia FM Week 2025. For professional
consulting, verification reports, or adaptation of these methods, see
[konnov.phd][] and [protocols-made-fun.com][].

## Table of Contents

- [TLA+ Specification](#tla-specification)
- [Test Harness](#test-harness)
- [Running Tests](#running-tests)
- [Visualization Scripts](#visualization-scripts)
- [Requirements](#requirements)

---

## TLA+ Specification

The specification models the TFTP protocol as defined in [**RFC 1350**][RFC
1350] (basic TFTP), [RFC 2347][], [RFC 2348][], [RFC 2349][] (option
extensions), and [RFC 1123][] (clarifying timeouts and standard issues). This
specification focuses on
**read requests (RRQ)** and implements option negotiation for block size,
transfer size, and timeout values.

### What It Specifies

The specification models:

- **Client-server communication** over UDP with multiple concurrent clients
- **Read transfers** with block-by-block data transmission
- **Option negotiation** (OACK packets) for `blksize`, `tsize`, and `timeout`
- **Timeout and retransmission** behavior using a global synchronized clock
- **Error conditions** including option negotiation failures, invalid operations,
  and unknown transfer IDs
- **Packet loss and reordering** through non-deterministic symbolic execution
- **Duplicate packet handling** (both client and server retransmissions)

### Assumptions and Scope

**Assumptions:**
- Clients only perform read operations (RRQ); write requests (WRQ) are not modeled yet
- Global synchronized clock for timeout modeling (RFC 1123, RFC 2349)
- UDP packet delivery is modeled symbolically (packets may arrive, be lost, or arrive out of order)
- File contents are abstracted as sizes in bytes; actual data is not modeled
- Transfer mode is always "octet" (binary mode)

**Out of Scope:**
- Write requests (WRQ)
- "netascii" and "mail" transfer modes
- Physical network details (checksums, fragmentation, etc.)
- Disk I/O operations

### Specification Files

Located in `spec/`:

#### `tftp.tla`
The main specification module defining the TFTP protocol behavior.

**Constants:**
- `SERVER_IP`: IP address of the TFTP server
- `CLIENT_IPS`: Set of client IP addresses
- `PORTS`: Available port numbers (1024..65535)
- `FILES`: Mapping from filenames to their sizes in bytes

**Variables:**
- `packets`: Set of UDP packets in flight
- `serverTransfers`: Active transfers tracked by the server
- `clientTransfers`: Active transfers tracked by clients
- `clock`: Global synchronized clock value
- `lastAction`: The most recent action taken (for test generation)

**Key Transitions:**
- `ClientSendRRQ`: Client initiates a read request
- `ServerRecvRRQthenSendOack/Data/Error`: Server responds to RRQ
- `ClientRecvOACKthenSendAck/Error`: Client handles option negotiation
- `ClientRecvDATA`: Client receives data blocks
- `ServerSendDATA/ResendDATA`: Server sends new or retransmits data
- `ServerSendDup/ClientSendDup`: Handle duplicate packets
- `ServerTimeout/ClientCrash`: Timeout and crash handling
- `AdvanceClock`: Time progression

#### `MC2_tftp.tla`
Model checking configuration for Apalache with concrete parameter values.

**Configuration:**
- Server: `172.20.0.10`
- Clients: `172.20.0.11`, `172.20.0.12`
- Files: `file1` (1024 bytes), `file2` (2099 bytes), `file3` (12345 bytes)
- Ports: `1024..65535`

Defines view abstraction (`MeasureView`) to reduce state space by abstracting transfer details.

#### `typedefs.tla`
Type definitions for Apalache type checking.

Defines structured types for:
- UDP packets (`$udpPacket`)
- TFTP payloads (RRQ, OACK, DATA, ACK, ERROR)
- Transfer state (`$transfer`)
- Actions (`$action`) including all protocol operations

#### `util.tla`
Utility operators:
- `SetAsFun`: Convert set of pairs to TLA+ function
- `mk_options`: Create option map for TFTP option negotiation

---

## Test Harness

The test harness located in `test-harness/` generates concrete test cases by exploring symbolic executions of the TLA+ specification using Apalache's JSON-RPC API.

### Architecture Overview

The harness orchestrates three components:

1. **Apalache Server**: Symbolic execution engine for TLA+ specifications
2. **Python Orchestrator**: Drives test generation and coordinates execution
3. **Docker Containers**: Run actual TFTP server (tftp-hpa) and test clients

### Core Components

#### `harness.py`
**Main test orchestrator** that coordinates symbolic execution and test generation.

**Key responsibilities:**
- Start and manage Apalache server
- Load TLA+ specification and explore symbolic executions
- For each symbolic execution step:
  - Query available transitions from Apalache
  - Select enabled transitions (randomly)
  - Execute corresponding TFTP operations in Docker
  - Validate SUT (System Under Test) responses against specification
- Generate test traces and save results

**Main classes:**
- `TftpTestHarness`: Orchestrates the entire testing process
  - `execute_sut_operation`: Run actual TFTP operations
  - `generate_test_run`: Create one symbolic test execution
  - `setup_logging`: Configure per-run logging
  - `start_apalache`: Start Apalache server
  - `load_specification`: Load TLA+ spec via JSON-RPC
  - `setup_docker`: Initialize Docker environment
  - `save_test_run`: Save traces, logs, and results

#### `docker_manager.py`
**Docker orchestration** for TFTP server and clients.

**Responsibilities:**
- Build Docker image with tftp-hpa and Python client
- Create isolated network (172.20.0.0/24)
- Start TFTP server container
- Start multiple client containers
- Send TFTP commands to clients via TCP control port
- Retrieve server logs and syslog
- Reset containers between test runs
- Cleanup on shutdown

**Network topology:**
- **Server**: `172.20.0.10:69` (TFTP), ports 1024-1027 (data transfers)
- **Clients**: `172.20.0.11`, `172.20.0.12` with control port 5000

#### `tftp_client_docker.py`
**TFTP client** running inside Docker containers.

**Functionality:**
- Listen on TCP control port (5000) for commands from harness
- Execute TFTP operations: RRQ, ACK, ERROR
- Capture UDP packets received from server
- Return packet details to harness in JSON format
- Buffer packets for validation against spec

**Commands supported:**
- `rrq`: Send read request with options
- `ack`: Send acknowledgment for block
- `error`: Send error packet
- `get_packets`: Retrieve buffered packets from server

#### `Dockerfile`
Docker image configuration:
- Base: Ubuntu with tftp-hpa server
- Python 3 with required libraries
- Pre-configured test files (file1, file2, file3)
- TFTP server with syslog logging
- Client control script

#### `pyproject.toml`
Poetry project configuration:
- Dependencies: `requests`, `itf-py`, `apalache-rpc-client`, `orjson`, `frozendict`
- Python 3.9+
- Development tools configuration

---

## Running Tests

### Prerequisites

1. **Install Apalache**: Pull a docker image:
   ```bash
   docker pull ghcr.io/apalache-mc/apalache
   ```

   You can checker whether it is working properly by running:
   ```bash
   docker run --rm -v$(pwd)':/var/apalache' -p 8822:8822 \
     ghcr.io/apalache-mc/apalache:latest server --server-type=explorer \
     --hostname=0.0.0.0
   ```

2. **Install Docker**: Required for running TFTP server and clients
3. **Install Python 3.9+**: Required for test harness

### Installation

```bash
# Create and activate virtual environment
pyenv virtualenv 3.13.3 tftp-symbolic-testing
pyenv activate tftp-symbolic-testing

# Install dependencies with poetry
cd test-harness

# Or use Poetry
poetry install
```

### Basic Usage

Generate test cases without Docker (symbolic execution only):

```bash
cd test-harness
python harness.py --tests 10 --steps 100
```

**Arguments:**
- `--tests N`: Number of test runs to generate (default: 10)
- `--steps N`: Maximum steps per test run (default: 100)
- `--docker`: Enable Docker to run actual TFTP operations (optional)

### Running with Docker

To execute actual TFTP operations against a real server:

```bash
cd test-harness
python harness.py --tests 10 --steps 100 --docker
```

**What happens:**
1. Builds Docker image with tftp-hpa server
2. Creates isolated network
3. Starts TFTP server and client containers
4. For each test run:
   - Generates symbolic execution trace
   - Executes TFTP operations in Docker
   - Validates server responses against spec
   - Saves results to `test-results/run_NNNN/`

### Output Structure

Each test run creates a directory `test-results/run_NNNN/` containing:

- **`python_harness.log`**: Complete test execution log with timestamps
- **`transitions.txt`**: Sequence of transition indices taken
- **`commands.json`**: TFTP operations executed with responses
- **`divergence_trace.itf.json`**: ITF trace when test diverges from spec (if applicable)
- **`tftpd_server.log`**: TFTP server container logs (with `--docker`)
- **`tftpd_syslog.log`**: Server syslog output (with `--docker`)

### Example Output

```
test-results/
├── run_0001/
│   ├── python_harness.log      # Test execution log
│   ├── transitions.txt         # [0, 3, 15, 7, ...]
│   ├── commands.json           # TFTP operations
│   └── divergence_trace.itf.json  # (if test diverged)
├── run_0002/
│   └── ...
└── run_0003/
    └── ...
```

---

## Visualization Scripts

Located in `scripts/`, these tools help analyze and visualize test results.

### `log_to_mermaid.py`

Convert test harness logs to Mermaid sequence diagrams.

**Usage:**
```bash
python scripts/log_to_mermaid.py test-harness/test-results/run_0001/python_harness.log output.mmd
```

**Features:**
- Parses `python_harness.log` files
- Extracts TFTP message flow between clients and server
- Generates Mermaid sequence diagram
- Distinguishes action types:
  - **Solid arrows (-->>)**: Spec actions (client operations)
  - **Dashed arrows (-->>)**: SUT packets (server responses)
  - **Self-loops**: Timeout events
  - **Global notes**: Clock advances, test divergence
- Filters to show only the last test run (when logs contain retries)

**Output:** Mermaid diagram showing complete message flow with participants, packets, and timing.

### `itf_to_mermaid.py`

Convert ITF JSON traces to Mermaid sequence diagrams.

**Usage:**
```bash
python scripts/itf_to_mermaid.py test-harness/test-results/run_0001/divergence_trace.itf.json output.mmd
```

**Features:**
- Parses ITF JSON format (Apalache trace format)
- Extracts state transitions and packet exchanges
- Generates sequence diagram from formal trace
- Useful for visualizing divergence traces

**When to use:** Analyzing symbolic execution traces, especially when tests diverge from the specification.

### `log_to_plot.py`

Analyze timing from test harness logs and produce stacked bar charts.

**Usage:**
```bash
# Interactive plot
python scripts/log_to_plot.py test-harness/test-results

# Save to file
python scripts/log_to_plot.py test-harness/test-results --output timing_plot.png
```

**Features:**
- Reads all `python_harness.log` files in directory
- Categorizes operations into timing buckets:
  - **JSON-RPC Client** (Blue): Apalache communication
  - **TFTP Operations** (Green): Protocol operations
  - **Docker Operations** (Red): Container management
  - **Clock Advancement** (Orange): Time spent in sleep()
  - **Other** (Gray): Test orchestration
- Produces stacked bar chart showing time distribution
- Prints summary statistics with percentages

**Requirements:** `matplotlib`, `numpy`

### Shell Scripts

#### `render_log_traces.sh`

Batch convert all log files to Mermaid diagrams and render as PNG.

**Usage:**
```bash
./scripts/render_log_traces.sh
```

Requires: `mmdc` (Mermaid CLI) for rendering diagrams to PNG.

#### `render_itf_traces.sh`

Batch convert all ITF JSON traces to Mermaid diagrams.

**Usage:**
```bash
./scripts/render_itf_traces.sh
```

---

## Requirements

### System Requirements

- **Operating System**: Linux, macOS, or WSL2 on Windows
- **Python**: 3.9 or higher
- **Docker**: 20.10 or higher
- **Apalache**: Latest version from [apalache-mc.org][]
- **Memory**: 4GB RAM minimum (8GB recommended for larger test runs)

### Python Dependencies

Core:
- `requests` - HTTP client for JSON-RPC
- `itf-py` - ITF trace format support
- `orjson` - Fast JSON serialization
- `frozendict` - Immutable dictionaries

Visualization (optional):
- `matplotlib` - Plotting library
- `numpy` - Numerical operations

### Installing Dependencies

```bash
# Using pip
pip install requests itf-py orjson frozendict matplotlib numpy

# Using Poetry (recommended)
cd test-harness
poetry install
```

### Docker Image

The Dockerfile creates an Ubuntu-based image with:
- `tftp-hpa` server (in.tftpd)
- Python 3 with networking libraries
- Pre-created test files (1KB, 2KB, 12KB)
- Syslog for TFTP server logging
- Client control script for test execution

---

## Project Structure

```
tftp-symbolic-testing/
├── spec/                          # TLA+ specification
│   ├── tftp.tla                  # Main TFTP protocol spec
│   ├── MC2_tftp.tla              # Model checking configuration
│   ├── typedefs.tla              # Type definitions
│   └── util.tla                  # Utility operators
│
├── test-harness/                  # Test generation harness
│   ├── harness.py                # Main orchestrator
│   ├── client.py                 # JSON-RPC client for Apalache
│   ├── server.py                 # Apalache server manager
│   ├── docker_manager.py         # Docker orchestration
│   ├── tftp_client_docker.py     # TFTP client in container
│   ├── Dockerfile                # Container image
│   ├── pyproject.toml            # Python dependencies
│   ├── files/                    # Test files (file1, file2, file3)
│   └── test-results/             # Generated test runs
│
└── scripts/                       # Visualization and analysis
    ├── log_to_mermaid.py         # Log → Mermaid converter
    ├── itf_to_mermaid.py         # ITF → Mermaid converter
    ├── log_to_plot.py            # Timing analysis
    ├── render_log_traces.sh      # Batch log rendering
    └── render_itf_traces.sh      # Batch ITF rendering
```

---

## Contact

For questions, consulting, or collaboration:
- Website: [konnov.phd][]
- Technical blog: [protocols-made-fun.com][]

## Citation

If you use this work in research, please cite:

```
Igor Konnov. Symbolic Testing of TFTP with Apalache.
Nvidia FM Week 2025.
```

## License

See [LICENSE](./LICENSE) file for details.

[konnov.phd]: https://konnov.phd
[protocols-made-fun.com]: https://protocols-made-fun.com
[TFTP]: https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol
[Apalache]: https://apalache-mc.org/
[apalache-mc.org]: https://apalache-mc.org/
[RFC 1350]: https://datatracker.ietf.org/doc/html/rfc1350
[RFC 2347]: https://datatracker.ietf.org/doc/html/rfc2347
[RFC 2348]: https://datatracker.ietf.org/doc/html/rfc2348
[RFC 2349]: https://datatracker.ietf.org/doc/html/rfc2349
[RFC 1123]: https://datatracker.ietf.org/doc/html/rfc1123