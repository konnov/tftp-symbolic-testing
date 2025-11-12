#!/usr/bin/env python3
"""
Docker orchestration for TFTP test harness.

Manages Docker containers, networks, and communication with TFTP clients.

Claude Sonnet 4.5 and Igor Konnov, 2025
"""

import json
import logging
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


class DockerManager:
    """Manages Docker containers for TFTP testing."""

    # Constants from MC2_tftp.tla
    SERVER_IP = "172.20.0.10"
    CLIENT_IPS = ["172.20.0.11", "172.20.0.12"]
    PORT_RANGE = "1024:1027"
    CONTROL_PORT = 15000  # Changed from 5000 to avoid conflict with macOS ControlCenter

    def __init__(self, test_harness_dir: str):
        """
        Initialize the Docker manager.

        Args:
            test_harness_dir: Directory containing test harness files
        """
        self.test_harness_dir = Path(test_harness_dir)
        self.log = logging.getLogger(__name__)
        self.network_name = "tftp-test-network"
        self.server_container = None
        self.client_containers = []
        self.image_name = "tftp-test-harness:latest"

    def build_image(self) -> bool:
        """Build the Docker image."""
        self.log.info("Building Docker image...")

        try:
            result = subprocess.run(
                ["docker", "build", "-t", self.image_name, "."],
                cwd=self.test_harness_dir,
                check=True,
                capture_output=True,
                text=True
            )
            self.log.info("Docker image built successfully")
            return True

        except subprocess.CalledProcessError as e:
            self.log.error(f"Failed to build Docker image: {e.stderr}")
            return False

    def create_network(self) -> bool:
        """Create a Docker network for TFTP testing."""
        self.log.info(f"Creating Docker network: {self.network_name}")

        try:
            # Check if network already exists
            result = subprocess.run(
                ["docker", "network", "ls", "--filter", f"name={self.network_name}", "--format", "{{.Name}}"],
                capture_output=True,
                text=True,
                check=True
            )

            if self.network_name in result.stdout:
                self.log.info(f"Network {self.network_name} already exists")
                return True

            # Create the network
            subprocess.run(
                ["docker", "network", "create", "--subnet=172.20.0.0/24", self.network_name],
                check=True,
                capture_output=True,
                text=True
            )
            self.log.info(f"Network {self.network_name} created")
            return True

        except subprocess.CalledProcessError as e:
            self.log.error(f"Failed to create network: {e.stderr}")
            return False

    def start_server(self) -> bool:
        """Start the TFTP server container."""
        self.log.info("Starting TFTP server container...")

        try:
            # Stop and remove existing container if it exists
            self.stop_server()

            # Start the server container
            cmd = [
                "docker", "run", "-d",
                "--name", "tftp-server",
                "--network", self.network_name,
                "--ip", self.SERVER_IP,
                "-e", f"SERVER_IP={self.SERVER_IP}",
                "-e", f"PORT_RANGE={self.PORT_RANGE}",
                "-p", "69:69/udp",
                "-p", f"{self.PORT_RANGE.replace(':', '-')}:{self.PORT_RANGE.replace(':', '-')}/udp",
                self.image_name
            ]

            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.server_container = result.stdout.strip()
            self.log.info(f"TFTP server started: {self.server_container[:12]}")

            # Wait for server to be ready
            time.sleep(2)

            return True

        except subprocess.CalledProcessError as e:
            self.log.error(f"Failed to start server: {e.stderr}")
            return False

    def start_client(self, client_ip: str) -> Optional[str]:
        """
        Start a TFTP client container.

        Args:
            client_ip: IP address for the client

        Returns:
            Container ID if successful, None otherwise
        """
        self.log.info(f"Starting TFTP client container with IP {client_ip}...")

        try:
            # Container name based on IP
            container_name = f"tftp-client-{client_ip.replace('.', '-')}"

            # Calculate unique host port for each client (15001, 15002, etc.)
            client_index = self.CLIENT_IPS.index(client_ip)
            host_port = self.CONTROL_PORT + client_index + 1

            # Stop and remove existing container if it exists
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True,
                text=True
            )

            # Start the client container
            cmd = [
                "docker", "run", "-d",
                "--name", container_name,
                "--network", self.network_name,
                "--ip", client_ip,
                "-e", f"CLIENT_IP={client_ip}",
                "-e", f"SERVER_IP={self.SERVER_IP}",
                "-e", f"CONTROL_PORT={self.CONTROL_PORT}",
                "-p", f"{host_port}:{self.CONTROL_PORT}",  # Map unique host port to container's CONTROL_PORT
                self.image_name,
                "python3", "/usr/local/bin/tftp_client.py",
                "--client-ip", client_ip,
                "--server-ip", self.SERVER_IP,
                "--control-port", str(self.CONTROL_PORT)
            ]

            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            container_id = result.stdout.strip()
            self.client_containers.append(container_id)
            self.log.info(f"TFTP client started: {container_id[:12]}")

            # Wait for client to be ready
            time.sleep(2)

            return container_id

        except subprocess.CalledProcessError as e:
            self.log.error(f"Failed to start client: {e.stderr}")
            return None

    def send_command_to_client(self, client_ip: str, command: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Send a command to a TFTP client via TCP control port.

        Args:
            client_ip: IP of the client
            command: Command dictionary

        Returns:
            Response dictionary or None on error
        """
        
        try:
            # Calculate the host port for this client
            client_index = self.CLIENT_IPS.index(client_ip)
            host_port = self.CONTROL_PORT + client_index + 1

            self.log.info(f"Sending command to client {client_ip} over {host_port}: {command}")

            # Connect to client control port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(("localhost", host_port))

            # Send command (length-prefixed JSON)
            cmd_data = json.dumps(command).encode('utf-8')
            sock.send(struct.pack("!I", len(cmd_data)))
            sock.send(cmd_data)

            # Receive response (length-prefixed JSON)
            length_data = sock.recv(4)
            if not length_data:
                return None

            msg_length = struct.unpack("!I", length_data)[0]
            response_data = sock.recv(msg_length)
            response = json.loads(response_data.decode('utf-8'))

            sock.close()

            self.log.info(f"Received response: {response}")
            return response

        except Exception as e:
            self.log.error(f"Error communicating with client: {e}")
            return None

    def get_server_logs(self) -> str:
        """Get the logs from the TFTP server container."""
        try:
            result = subprocess.run(
                ["docker", "logs", "tftp-server"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout + result.stderr
        except subprocess.CalledProcessError as e:
            self.log.error(f"Failed to get server logs: {e.stderr}")
            return f"Error retrieving server logs: {e.stderr}"
        except Exception as e:
            self.log.error(f"Unexpected error getting server logs: {e}")
            return f"Error retrieving server logs: {e}"

    def get_syslog(self) -> str:
        """Get the syslog from the TFTP server container."""
        try:
            result = subprocess.run(
                ["docker", "exec", "tftp-server", "cat", "/var/log/syslog"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.log.error(f"Failed to get syslog: {e.stderr}")
            return f"Error retrieving syslog: {e.stderr}"
        except Exception as e:
            self.log.error(f"Unexpected error getting syslog: {e}")
            return f"Error retrieving syslog: {e}"

    def stop_server(self):
        """Stop the TFTP server container."""
        try:
            subprocess.run(
                ["docker", "rm", "-f", "tftp-server"],
                capture_output=True,
                text=True
            )
            self.log.info("TFTP server stopped")
        except Exception as e:
            self.log.warning(f"Error stopping server: {e}")

    def stop_clients(self):
        """Stop all client containers."""
        for container_id in self.client_containers:
            try:
                subprocess.run(
                    ["docker", "rm", "-f", container_id],
                    capture_output=True,
                    text=True
                )
            except Exception as e:
                self.log.warning(f"Error stopping client {container_id[:12]}: {e}")

        self.client_containers = []
        self.log.info("All clients stopped")

    def cleanup(self):
        """Clean up all Docker resources."""
        self.log.info("Cleaning up Docker resources...")
        self.stop_clients()
        self.stop_server()

        # Optionally remove network
        try:
            subprocess.run(
                ["docker", "network", "rm", self.network_name],
                capture_output=True,
                text=True
            )
            self.log.info(f"Network {self.network_name} removed")
        except Exception as e:
            self.log.warning(f"Error removing network: {e}")

    def setup(self) -> bool:
        """Set up the complete Docker environment."""
        self.log.info("Setting up Docker environment...")

        if not self.build_image():
            return False

        if not self.create_network():
            return False

        if not self.start_server():
            return False

        # Start client containers for each client IP
        for client_ip in self.CLIENT_IPS:
            if not self.start_client(client_ip):
                self.log.error(f"Failed to start client {client_ip}")
                self.cleanup()
                return False

        self.log.info("Docker environment ready")
        return True
