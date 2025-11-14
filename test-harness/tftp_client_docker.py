#!/usr/bin/env python3
"""
TFTP Client for Docker - Receives commands over TCP and executes TFTP operations.

This client script runs inside a Docker container and:
1. Listens for commands on a TCP control port (5000)
2. Executes TFTP operations (read/write) based on commands
3. Sends responses back over the TCP connection

Claude Sonnet 4.5 and Igor Konnov, 2025
"""

import json
import logging
import select
import socket
import struct
import sys
from collections import deque
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

# The timeout we are using for socket operations.
# Since TFTP is using UDP, we do not wait for response too long.
SOCKET_TIMEOUT = 1


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

        # Multiple UDP sockets for TFTP operations (port -> socket mapping)
        self.udp_sockets: Dict[int, socket.socket] = {}

        # Buffer for received UDP packets
        self.packet_buffer = deque()

        # TCP control server socket
        self.control_socket: Optional[socket.socket] = None

    def setup_logging(self):
        """Configure logging."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            stream=sys.stdout
        )

    def init_udp_socket(self, source_port: Optional[int] = None) -> int:
        """
        Initialize UDP socket for TFTP operations.

        Args:
            source_port: Specific port to bind to, or None for random port

        Returns:
            The actual port number that was bound
        """
        # Check if we already have a socket for this port
        if source_port and source_port in self.udp_sockets:
            self.log.info(f"UDP socket already exists for port {source_port}")
            return source_port

        # Create new socket
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setblocking(False)

        if source_port:
            udp_sock.bind((self.client_ip, source_port))
        else:
            udp_sock.bind((self.client_ip, 0))

        actual_port = udp_sock.getsockname()[1]
        self.udp_sockets[actual_port] = udp_sock
        self.log.info(f"UDP socket initialized on {self.client_ip}:{actual_port}")

        return actual_port

    def close_udp_socket(self, port: Optional[int] = None):
        """
        Close UDP socket(s).

        Args:
            port: Specific port to close, or None to close all sockets
        """
        if port:
            # Close specific socket
            if port in self.udp_sockets:
                self.udp_sockets[port].close()
                del self.udp_sockets[port]
                self.log.info(f"UDP socket on port {port} closed")
        else:
            # Close all sockets
            for p, sock in self.udp_sockets.items():
                sock.close()
                self.log.info(f"UDP socket on port {p} closed")
            self.udp_sockets.clear()

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

    def encode_error(self, error_code: int, error_msg: str) -> bytes:
        """
        Encode an ERROR packet.

        Args:
            error_code: TFTP error code (0-7)
            error_msg: Error message string

        Returns:
            Encoded ERROR packet
        """
        # ERROR packet format: opcode(2) | error_code(2) | error_msg(string) | 0
        error_msg_bytes = error_msg.encode('utf-8')
        return struct.pack("!HH", OPCODE_ERROR, error_code) + error_msg_bytes + b'\x00'

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
        Send a Read Request (non-blocking).

        Args:
            filename: File to read
            options: TFTP options
            source_port: Specific source port to use (or random if None)

        Returns:
            Dictionary containing send status
        """
        self.log.info(f"Sending RRQ for file: {filename}")

        try:
            # Initialize UDP socket for this port
            actual_port = self.init_udp_socket(source_port)

            # Get the socket for this port
            sock = self.udp_sockets[actual_port]

            # Encode and send RRQ
            rrq_packet = self.encode_rrq(filename, "octet", options)
            sock.sendto(rrq_packet, (self.server_ip, 69))
            self.log.info(f"Sent RRQ to {self.server_ip}:69 from port {actual_port}")

            return {
                'status': 'sent',
                'packet_type': 'RRQ',
                'filename': filename,
                'source_port': actual_port
            }

        except Exception as e:
            self.log.error(f"Error sending RRQ: {e}")
            return {'error': str(e)}

    def send_ack(self, block_num: int, dest_port: int, source_port: Optional[int] = None) -> Dict[str, Any]:
        """
        Send an ACK packet (non-blocking).

        Args:
            block_num: Block number to acknowledge
            dest_port: Server port to send to
            source_port: Client source port

        Returns:
            Send status information
        """
        self.log.info(f"Sending ACK for block {block_num}")

        try:
            # Initialize UDP socket for this port
            actual_port = self.init_udp_socket(source_port)

            # Get the socket for this port
            sock = self.udp_sockets[actual_port]

            ack_packet = self.encode_ack(block_num)
            sock.sendto(ack_packet, (self.server_ip, dest_port))
            self.log.info(f"Sent ACK to {self.server_ip}:{dest_port} from port {actual_port}")

            return {
                'status': 'sent',
                'packet_type': 'ACK',
                'block_num': block_num,
                'source_port': actual_port
            }

        except Exception as e:
            self.log.error(f"Error sending ACK: {e}")
            return {'error': str(e)}

    def send_error(self, error_code: int, error_msg: str, dest_port: int, source_port: Optional[int] = None) -> Dict[str, Any]:
        """
        Send an ERROR packet (non-blocking).

        Args:
            error_code: TFTP error code (0-7)
            error_msg: Error message
            dest_port: Server port to send to
            source_port: Client source port

        Returns:
            Send status information
        """
        self.log.info(f"Sending ERROR (code={error_code}, msg={error_msg})")

        try:
            # Initialize UDP socket for this port
            actual_port = self.init_udp_socket(source_port)

            # Get the socket for this port
            sock = self.udp_sockets[actual_port]

            error_packet = self.encode_error(error_code, error_msg)
            sock.sendto(error_packet, (self.server_ip, dest_port))
            self.log.info(f"Sent ERROR to {self.server_ip}:{dest_port} from port {actual_port}")

            return {
                'status': 'sent',
                'packet_type': 'ERROR',
                'error_code': error_code,
                'error_msg': error_msg,
                'source_port': actual_port
            }

        except Exception as e:
            self.log.error(f"Error sending ERROR packet: {e}")
            return {'error': str(e)}

    def get_buffered_packets(self) -> Dict[str, Any]:
        """
        Retrieve and clear all buffered packets.

        Returns:
            Dictionary containing list of buffered packets
        """
        packets = list(self.packet_buffer)
        self.packet_buffer.clear()

        self.log.info(f"Retrieved {len(packets)} buffered packet(s)")

        return {
            'status': 'ok',
            'packet_count': len(packets),
            'packets': packets
        }

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
            filename = command.get('filename')
            if not filename:
                return {'error': 'Missing required field: filename'}
            return self.send_rrq(
                filename=filename,
                options=command.get('options'),
                source_port=command.get('source_port')
            )

        elif cmd_type == 'ack':
            block_num = command.get('block_num')
            dest_port = command.get('dest_port')
            if block_num is None or dest_port is None:
                return {'error': 'Missing required fields: block_num or dest_port'}
            return self.send_ack(
                block_num=block_num,
                dest_port=dest_port,
                source_port=command.get('source_port')
            )

        elif cmd_type == 'error':
            error_code = command.get('error_code')
            error_msg = command.get('error_msg', '')
            dest_port = command.get('dest_port')
            if error_code is None or dest_port is None:
                return {'error': 'Missing required fields: error_code or dest_port'}
            return self.send_error(
                error_code=error_code,
                error_msg=error_msg,
                dest_port=dest_port,
                source_port=command.get('source_port')
            )

        elif cmd_type == 'get_packets':
            return self.get_buffered_packets()

        elif cmd_type == 'close_port':
            port = command.get('port')
            if port is None:
                return {'error': 'Missing required field: port'}
            self.close_udp_socket(port)
            return {'status': 'closed', 'port': port}

        else:
            return {'error': f'Unknown command type: {cmd_type}'}

    def run_control_server(self):
        """Run the control server using select() to handle both TCP commands and UDP packets."""
        self.log.info(f"Starting control server on {self.client_ip}:{self.control_port}")

        self.control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.control_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.control_socket.bind((self.client_ip, self.control_port))
        self.control_socket.listen(1)
        self.control_socket.setblocking(False)

        self.log.info("Control server listening...")

        # No active control connection initially
        active_conn = None

        while True:
            try:
                # Build list of sockets to monitor
                read_list = [self.control_socket] + list(self.udp_sockets.values())
                if active_conn:
                    read_list.append(active_conn)

                # Use select with timeout to multiplex I/O
                readable, _, _ = select.select(read_list, [], [], 0.1)

                for sock in readable:
                    # Handle new TCP control connection
                    if sock is self.control_socket:
                        conn, addr = sock.accept()
                        self.log.info(f"Control connection from {addr}")
                        active_conn = conn

                    # Handle data from active TCP control connection
                    elif sock is active_conn:
                        try:
                            # Receive command (length-prefixed JSON)
                            length_data = conn.recv(4)
                            if not length_data:
                                conn.close()
                                active_conn = None
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
                            active_conn = None
                        except Exception as e:
                            self.log.error(f"Error handling control connection: {e}", exc_info=True)
                            if active_conn:
                                active_conn.close()
                                active_conn = None

                    # Handle UDP packet
                    elif sock in self.udp_sockets.values():
                        try:
                            data, addr = sock.recvfrom(65536)
                            local_port = sock.getsockname()[1]

                            packet_info = self.decode_packet(data)
                            packet_info['src_ip'] = addr[0]
                            packet_info['src_port'] = addr[1]
                            packet_info['dest_ip'] = self.client_ip
                            packet_info['dest_port'] = local_port

                            # Add to buffer
                            self.packet_buffer.append(packet_info)

                            self.log.info(f"Buffered packet: {packet_info.get('opcode_name', 'UNKNOWN')} from {addr} to port {local_port}")
                        except Exception as e:
                            self.log.error(f"Error receiving UDP packet: {e}")

            except KeyboardInterrupt:
                self.log.info("Received interrupt signal")
                break
            except Exception as e:
                self.log.error(f"Error in main loop: {e}", exc_info=True)

    def shutdown(self):
        """Shutdown the client and cleanup resources."""
        self.log.info("Shutting down TFTP client")

        # Close all UDP sockets
        self.close_udp_socket()

        # Close control socket
        if self.control_socket:
            self.control_socket.close()
            self.control_socket = None

        self.log.info("TFTP client shutdown complete")


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
        client.shutdown()
        sys.exit(0)


if __name__ == "__main__":
    main()
