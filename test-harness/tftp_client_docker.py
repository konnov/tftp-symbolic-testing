#!/usr/bin/env python3
"""
TFTP Client for Docker - Receives commands over TCP and executes TFTP operations.

This client script runs inside a Docker container and:
1. Listens for commands on a TCP control port (5000)
2. Executes TFTP operations (read/write) based on commands
3. Sends responses back over the TCP connection

Igor Konnov, 2025
"""

import json
import logging
import socket
import struct
import sys
from typing import Any, Dict, Optional, Tuple


# TFTP opcodes
OPCODE_RRQ = 1
OPCODE_WRQ = 2
OPCODE_DATA = 3
OPCODE_ACK = 4
OPCODE_ERROR = 5
OPCODE_OACK = 6

# Default TFTP parameters
DEFAULT_BLKSIZE = 512
DEFAULT_TIMEOUT = 5


class TftpClient:
    """TFTP client that executes operations based on TCP commands."""

    def __init__(self, client_ip: str, server_ip: str, control_port: int = 5000):
        """
        Initialize the TFTP client.

        Args:
            client_ip: IP address of this client
            server_ip: IP address of the TFTP server
            control_port: TCP port for receiving commands
        """
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.control_port = control_port
        self.log = logging.getLogger(__name__)

    def setup_logging(self):
        """Configure logging."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            stream=sys.stdout
        )

    def encode_rrq(self, filename: str, mode: str = "octet", options: Optional[Dict[str, int]] = None) -> bytes:
        """
        Encode a Read Request (RRQ) packet.

        Args:
            filename: Name of the file to read
            mode: Transfer mode (octet, netascii, mail)
            options: Optional TFTP options (blksize, tsize, timeout)

        Returns:
            Encoded RRQ packet
        """
        packet = struct.pack("!H", OPCODE_RRQ)
        packet += filename.encode('ascii') + b'\x00'
        packet += mode.encode('ascii') + b'\x00'

        if options:
            for key, value in options.items():
                packet += key.encode('ascii') + b'\x00'
                packet += str(value).encode('ascii') + b'\x00'

        return packet

    def encode_wrq(self, filename: str, mode: str = "octet", options: Optional[Dict[str, int]] = None) -> bytes:
        """
        Encode a Write Request (WRQ) packet.

        Args:
            filename: Name of the file to write
            mode: Transfer mode
            options: Optional TFTP options

        Returns:
            Encoded WRQ packet
        """
        packet = struct.pack("!H", OPCODE_WRQ)
        packet += filename.encode('ascii') + b'\x00'
        packet += mode.encode('ascii') + b'\x00'

        if options:
            for key, value in options.items():
                packet += key.encode('ascii') + b'\x00'
                packet += str(value).encode('ascii') + b'\x00'

        return packet

    def encode_ack(self, block_num: int) -> bytes:
        """Encode an ACK packet."""
        return struct.pack("!HH", OPCODE_ACK, block_num)

    def decode_packet(self, data: bytes) -> Dict[str, Any]:
        """
        Decode a TFTP packet.

        Args:
            data: Raw packet data

        Returns:
            Dictionary containing packet information
        """
        if len(data) < 2:
            return {'opcode': 0, 'error': 'Packet too short'}

        opcode = struct.unpack("!H", data[:2])[0]

        if opcode == OPCODE_DATA:
            if len(data) < 4:
                return {'opcode': opcode, 'error': 'Invalid DATA packet'}
            block_num = struct.unpack("!H", data[2:4])[0]
            payload = data[4:]
            return {
                'opcode': opcode,
                'opcode_name': 'DATA',
                'block_num': block_num,
                'data_length': len(payload)
            }

        elif opcode == OPCODE_ACK:
            if len(data) < 4:
                return {'opcode': opcode, 'error': 'Invalid ACK packet'}
            block_num = struct.unpack("!H", data[2:4])[0]
            return {
                'opcode': opcode,
                'opcode_name': 'ACK',
                'block_num': block_num
            }

        elif opcode == OPCODE_ERROR:
            if len(data) < 4:
                return {'opcode': opcode, 'error': 'Invalid ERROR packet'}
            error_code = struct.unpack("!H", data[2:4])[0]
            error_msg = data[4:].decode('ascii', errors='ignore').rstrip('\x00')
            return {
                'opcode': opcode,
                'opcode_name': 'ERROR',
                'error_code': error_code,
                'error_msg': error_msg
            }

        elif opcode == OPCODE_OACK:
            # Parse options
            options = {}
            parts = data[2:].split(b'\x00')
            for i in range(0, len(parts) - 1, 2):
                if parts[i]:
                    key = parts[i].decode('ascii', errors='ignore')
                    value = parts[i + 1].decode('ascii', errors='ignore')
                    options[key] = value
            return {
                'opcode': opcode,
                'opcode_name': 'OACK',
                'options': options
            }

        else:
            return {'opcode': opcode, 'opcode_name': 'UNKNOWN'}

    def send_rrq(self, filename: str, options: Optional[Dict[str, int]] = None, 
                 source_port: Optional[int] = None) -> Dict[str, Any]:
        """
        Send a Read Request and handle the response.

        Args:
            filename: File to read
            options: TFTP options
            source_port: Specific source port to use (or random if None)

        Returns:
            Dictionary containing the response information
        """
        self.log.info(f"Sending RRQ for file: {filename}")

        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(DEFAULT_TIMEOUT)

        try:
            # Bind to specific port if requested
            if source_port:
                sock.bind((self.client_ip, source_port))
                self.log.info(f"Bound to {self.client_ip}:{source_port}")
            else:
                sock.bind((self.client_ip, 0))

            actual_port = sock.getsockname()[1]
            self.log.info(f"Using source port: {actual_port}")

            # Encode and send RRQ
            rrq_packet = self.encode_rrq(filename, "octet", options)
            sock.sendto(rrq_packet, (self.server_ip, 69))
            self.log.info(f"Sent RRQ to {self.server_ip}:69")

            # Receive response
            data, addr = sock.recvfrom(65536)
            response = self.decode_packet(data)
            response['src_ip'] = addr[0]
            response['src_port'] = addr[1]
            response['dest_ip'] = self.client_ip
            response['dest_port'] = actual_port

            self.log.info(f"Received {response.get('opcode_name', 'UNKNOWN')} from {addr}")

            return response

        except socket.timeout:
            self.log.error("Timeout waiting for response")
            return {'error': 'timeout'}

        except Exception as e:
            self.log.error(f"Error sending RRQ: {e}")
            return {'error': str(e)}

        finally:
            sock.close()

    def send_ack(self, block_num: int, dest_port: int, source_port: Optional[int] = None) -> Dict[str, Any]:
        """
        Send an ACK packet.

        Args:
            block_num: Block number to acknowledge
            dest_port: Server port to send to
            source_port: Client source port

        Returns:
            Response information
        """
        self.log.info(f"Sending ACK for block {block_num}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(DEFAULT_TIMEOUT)

        try:
            if source_port:
                sock.bind((self.client_ip, source_port))
            else:
                sock.bind((self.client_ip, 0))

            ack_packet = self.encode_ack(block_num)
            sock.sendto(ack_packet, (self.server_ip, dest_port))
            self.log.info(f"Sent ACK to {self.server_ip}:{dest_port}")

            # Try to receive next packet
            try:
                data, addr = sock.recvfrom(65536)
                response = self.decode_packet(data)
                response['src_ip'] = addr[0]
                response['src_port'] = addr[1]
                return response
            except socket.timeout:
                return {'status': 'ack_sent', 'timeout': True}

        except Exception as e:
            self.log.error(f"Error sending ACK: {e}")
            return {'error': str(e)}

        finally:
            sock.close()

    def handle_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle a command from the harness.

        Args:
            command: Command dictionary containing operation details

        Returns:
            Response dictionary
        """
        cmd_type = command.get('type')

        if cmd_type == 'rrq':
            return self.send_rrq(
                filename=command.get('filename'),
                options=command.get('options'),
                source_port=command.get('source_port')
            )

        elif cmd_type == 'ack':
            return self.send_ack(
                block_num=command.get('block_num'),
                dest_port=command.get('dest_port'),
                source_port=command.get('source_port')
            )

        else:
            return {'error': f'Unknown command type: {cmd_type}'}

    def run_control_server(self):
        """Run the TCP control server to receive commands."""
        self.log.info(f"Starting control server on {self.client_ip}:{self.control_port}")

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.client_ip, self.control_port))
        server_sock.listen(1)

        self.log.info("Control server listening...")

        while True:
            try:
                conn, addr = server_sock.accept()
                self.log.info(f"Control connection from {addr}")

                # Receive command (length-prefixed JSON)
                length_data = conn.recv(4)
                if not length_data:
                    conn.close()
                    continue

                msg_length = struct.unpack("!I", length_data)[0]
                cmd_data = conn.recv(msg_length)
                command = json.loads(cmd_data.decode('utf-8'))

                self.log.info(f"Received command: {command}")

                # Handle command
                response = self.handle_command(command)

                # Send response (length-prefixed JSON)
                response_data = json.dumps(response).encode('utf-8')
                conn.send(struct.pack("!I", len(response_data)))
                conn.send(response_data)

                conn.close()

            except Exception as e:
                self.log.error(f"Error handling control connection: {e}", exc_info=True)


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='TFTP Client for Docker')
    parser.add_argument('--client-ip', required=True, help='Client IP address')
    parser.add_argument('--server-ip', required=True, help='Server IP address')
    parser.add_argument('--control-port', type=int, default=5000, help='TCP control port')

    args = parser.parse_args()

    client = TftpClient(args.client_ip, args.server_ip, args.control_port)
    client.setup_logging()

    try:
        client.run_control_server()
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()
