"""
Apalache server management for Apalache JSON-RPC.

Igor Konnov, 2025
"""

import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

import requests

class ApalacheServer:
    """Manages the Apalache server process."""

    def __init__(self, log_dir: str, hostname: str, port: int = 8822):
        self.hostname = hostname
        self.port = port
        self.server_process = None
        self.log_dir = Path(log_dir)
        self.log = logging.getLogger(__name__)
        self.stdout_file = None
        self.stderr_file = None

    def start_server(self) -> bool:
        """Start the Apalache server in explorer mode."""
        # Check if server is already running
        if self._is_server_running():
            self.log.info(f"Apalache server is already running on port {self.port}")
            return True

        if self.hostname != "localhost":
            self.log.error(f"Apalache server is not running on {self.hostname}, and it's not localhost")
            return False

        self.log.info("Starting Apalache server in explorer mode...")

        # Find the apalache-mc executable
        apalache_cmd = self._find_apalache_executable()
        if not apalache_cmd:
            self.log.info("Error: Could not find apalache-mc executable")
            return False

        # Start the server
        cmd = [apalache_cmd, "server", "--server-type=explorer", f"--port={self.port}"]
        self.log.info(f"Running command: {' '.join(cmd)}")

        # Create log files for stdout and stderr to prevent deadlock
        # Ensure the log directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.stdout_file = os.path.join(self.log_dir, f"apalache_{self.port}.out")
        self.stderr_file = os.path.join(self.log_dir, f"apalache_{self.port}.err")

        self.log.info(f"Redirecting Apalache stdout to: {self.stdout_file}")
        self.log.info(f"Redirecting Apalache stderr to: {self.stderr_file}")

        try:
            with open(self.stdout_file, 'w') as stdout_f, open(self.stderr_file, 'w') as stderr_f:
                if os.name == 'posix':
                    self.server_process = subprocess.Popen(
                        cmd,
                        stdout=stdout_f,
                        stderr=stderr_f,
                        stdin=subprocess.DEVNULL,
                        preexec_fn=os.setsid,
                        text=True
                    )
                else:
                    self.server_process = subprocess.Popen(
                        cmd,
                        stdout=stdout_f,
                        stderr=stderr_f,
                        stdin=subprocess.DEVNULL,
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                        text=True
                    )

            stderr_f.close()
            stdout_f.close()

            # Wait for server to start
            max_retries = 30
            for i in range(max_retries):
                try:
                    response = requests.get(f"http://localhost:{self.port}/rpc", timeout=1)
                    if response.status_code in [200, 405]:  # 405 is expected for GET on JSON-RPC endpoint
                        self.log.info(f"Server started successfully on port {self.port}")
                        return True
                except requests.exceptions.RequestException:
                    pass

                # Check if process is still running
                if self.server_process.poll() is not None:
                    # Process has terminated
                    self.server_process.wait()  # Clean up the process
                    self.log.info(f"Server process terminated unexpectedly!")
                    self.log.info(f"Exit code: {self.server_process.returncode}")
                    self.log.info(f"Check logs in {self.stdout_file} and {self.stderr_file} for details")
                    return False

                time.sleep(1)
                if i % 5 == 0:  # Print progress every 5 seconds
                    self.log.info(f"Waiting for server to start... ({i+1}/{max_retries})")

            # Check process output before giving up
            if self.server_process.poll() is not None:
                self.server_process.wait()  # Clean up the process
                self.log.info(f"Server process terminated during startup!")
                self.log.info(f"Exit code: {self.server_process.returncode}")
                self.log.info(f"Check logs in {self.stdout_file} and {self.stderr_file} for details")
            else:
                self.log.info("Server process is still running but not responding to HTTP requests")
                self.log.info(f"Check logs in {self.stdout_file} and {self.stderr_file} for details")

            self.log.error("Error: Server failed to start within timeout")
            return False

        except Exception as e:
            self.log.error(f"Error starting server: {e}")
            return False

    def stop_server(self):
        """Stop the Apalache server."""

        if not self.server_process:
            self.log.warning("Server is running but not managed by this instance - cannot stop it")
        else:
            self.log.info("Stopping Apalache server...")
            self.server_process.terminate()
            try:
                self.server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.log.warning("Server process did not terminate gracefully, killing it...")
                self.server_process.kill()
                self.server_process.wait()
            self.server_process = None
            self.log.info("Apalache server stopped successfully")

    def _find_apalache_executable(self) -> Optional[str]:
        """Find the apalache-mc executable, either in PATH or in APALACHE_HOME/bin."""

        # First, check PATH
        apalache_cmd = shutil.which("apalache-mc")
        if apalache_cmd:
            return apalache_cmd

        # Check APALACHE_HOME environment variable
        apalache_home = os.environ.get("APALACHE_HOME")
        if apalache_home:
            apalache_home_bin = Path(apalache_home) / "bin" / "apalache-mc"
            if apalache_home_bin.exists() and os.access(apalache_home_bin, os.X_OK):
                return str(apalache_home_bin)

        return None

    def _is_server_running(self) -> bool:
        """Check if the Apalache server is running on the specified port."""
        try:
            response = requests.get(f"http://{self.hostname}:{self.port}/rpc", timeout=5)
            return response.status_code in [200, 405]  # 405 is expected for GET on JSON-RPC endpoint
        except requests.exceptions.RequestException:
            return False
