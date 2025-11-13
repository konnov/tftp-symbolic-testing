#!/usr/bin/env python3
"""
Convert Python test harness log files to Mermaid sequence diagrams.

This script reads a Python log file from the test harness and generates a
Mermaid sequence diagram showing the TFTP message flow between clients and servers.

This whole script is written by Claude Sonnet 4.5, 2025.
Don't try to read it, it's a spaghetti.

Usage:
    python log_to_mermaid.py input.log [output.mmd]
"""

import re
import sys
from typing import Any, Dict, List, Set, Tuple, Optional


def parse_namedtuple_packet(packet_str: str) -> Optional[Dict[str, Any]]:
    """
    Parse a namedtuple packet representation from log output.
    Example: UdpPacket(srcIp='172.20.0.11', srcPort=50000, destIp='172.20.0.10', destPort=69, payload=RRQ(...))
    """
    # Match UdpPacket pattern
    packet_match = re.search(r"UdpPacket\((.*?)\)(?:\s*$|\s*,)", packet_str)
    if not packet_match:
        return None

    fields_str = packet_match.group(1)

    # Parse fields
    result = {}

    # Extract srcIp
    src_ip_match = re.search(r"srcIp='([^']+)'", fields_str)
    if src_ip_match:
        result['srcIp'] = src_ip_match.group(1)

    # Extract srcPort
    src_port_match = re.search(r"srcPort=(\d+)", fields_str)
    if src_port_match:
        result['srcPort'] = int(src_port_match.group(1))

    # Extract destIp
    dest_ip_match = re.search(r"destIp='([^']+)'", fields_str)
    if dest_ip_match:
        result['destIp'] = dest_ip_match.group(1)

    # Extract destPort
    dest_port_match = re.search(r"destPort=(\d+)", fields_str)
    if dest_port_match:
        result['destPort'] = int(dest_port_match.group(1))

    # Extract payload - this is more complex as it's a nested namedtuple
    payload_match = re.search(r"payload=(\w+)\((.*?)\)(?:\)|$)", fields_str)
    if payload_match:
        payload_type = payload_match.group(1)
        payload_fields_str = payload_match.group(2)

        result['payloadTag'] = payload_type
        result['payload'] = {}

        # Parse payload fields based on type
        if payload_type == 'RRQ' or payload_type == 'WRQ':
            filename_match = re.search(r"filename='([^']+)'", payload_fields_str)
            if filename_match:
                result['payload']['filename'] = filename_match.group(1)

            mode_match = re.search(r"mode='([^']+)'", payload_fields_str)
            if mode_match:
                result['payload']['mode'] = mode_match.group(1)

            # Extract options if present
            options_match = re.search(r"options=({[^}]*}|\w+\([^)]*\))", payload_fields_str)
            if options_match:
                result['payload']['options'] = options_match.group(1)

        elif payload_type == 'DATA':
            block_match = re.search(r"blockNum=(\d+)", payload_fields_str)
            if block_match:
                result['payload']['blockNum'] = int(block_match.group(1))

            data_match = re.search(r"data=(\d+)", payload_fields_str)
            if data_match:
                result['payload']['data'] = int(data_match.group(1))

        elif payload_type == 'ACK':
            block_match = re.search(r"blockNum=(\d+)", payload_fields_str)
            if block_match:
                result['payload']['blockNum'] = int(block_match.group(1))

        elif payload_type == 'OACK':
            options_match = re.search(r"options=({[^}]*}|\w+\([^)]*\))", payload_fields_str)
            if options_match:
                result['payload']['options'] = options_match.group(1)

        elif payload_type == 'ERROR':
            error_code_match = re.search(r"errorCode=(\d+)", payload_fields_str)
            if error_code_match:
                result['payload']['errorCode'] = int(error_code_match.group(1))

            msg_match = re.search(r"msg='([^']*)'", payload_fields_str)
            if msg_match:
                result['payload']['msg'] = msg_match.group(1)

    return result if result else None


def format_payload(tag: str, payload: Dict[str, Any]) -> str:
    """Format payload for display in sequence diagram."""
    if tag == "RRQ":
        filename = payload.get("filename", "?")
        options = payload.get("options", "")
        if options and options != "{}":
            return f"RRQ({filename}, {options})"
        return f"RRQ({filename})"
    elif tag == "WRQ":
        filename = payload.get("filename", "?")
        options = payload.get("options", "")
        if options and options != "{}":
            return f"WRQ({filename}, {options})"
        return f"WRQ({filename})"
    elif tag == "DATA":
        block_num = payload.get("blockNum", "?")
        data_len = payload.get("data", "?")
        return f"DATA(blk={block_num}, {data_len}B)"
    elif tag == "ACK":
        block_num = payload.get("blockNum", "?")
        return f"ACK(blk={block_num})"
    elif tag == "OACK":
        options = payload.get("options", "")
        return f"OACK({options})"
    elif tag == "ERROR":
        error_code = payload.get("errorCode", "?")
        msg = payload.get("msg", "")
        return f"ERROR({error_code}, {msg})"
    else:
        return tag


def get_participant_id(ip: str, port: int) -> str:
    """Generate a valid Mermaid participant ID for an IP:port pair."""
    # Replace dots with underscores for valid Mermaid IDs
    ip_part = ip.replace(".", "_")
    return f"ip{ip_part}_port{port}"


def get_participant_label(ip: str, port: int) -> str:
    """Generate a human-readable label for an IP:port pair."""
    return f"{ip}:{port}"


def parse_log_file(log_file: str) -> List[Dict[str, Any]]:
    """
    Parse the log file and extract packet information and events in chronological order.

    Returns:
        List of entries (packets and events) in order of appearance.
    """
    entries: List[Dict[str, Any]] = []

    with open(log_file, 'r') as f:
        for line in f:
            # Skip non-INFO lines
            if ' - INFO - ' not in line:
                continue

            # Extract the message part after INFO
            parts = line.split(' - INFO - ', 1)
            if len(parts) < 2:
                continue

            message = parts[1].strip()

            # Look for packet information
            if 'Received packet:' in message or 'Sent packet:' in message or 'Expected packet' in message:
                # Extract packet from the message
                packet_data = parse_namedtuple_packet(message)
                if packet_data:
                    # Determine direction
                    if 'Received packet:' in message:
                        packet_data['direction'] = 'received'
                    elif 'Sent packet:' in message:
                        packet_data['direction'] = 'sent'
                        # Skip ACK packets from "Sent packet" logs - we get better info from "Sending ACK command"
                        if packet_data.get('payloadTag') == 'ACK':
                            continue
                    else:
                        packet_data['direction'] = 'expected'

                    packet_data['entry_type'] = 'packet'
                    entries.append(packet_data)

            # Look for "Sending ACK/ERROR command to client" with port information
            # We use these instead of "Sent packet" ACKs because they have correct port info
            elif 'Sending ACK command to client' in message or 'Sending ERROR command to client' in message:
                # Extract: "Sending ACK command to client: {'type': 'ack', 'block_num': 0, 'dest_port': 1024, 'source_port': 1024}"
                match = re.search(r'Sending (\w+) command to client: (\{.*)', message)
                if match:
                    cmd_type = match.group(1).upper()
                    command_str = match.group(2)

                    # Extract port information
                    dest_port_match = re.search(r"'dest_port': (\d+)", command_str)
                    source_port_match = re.search(r"'source_port': (\d+)", command_str)
                    block_num_match = re.search(r"'block_num': (\d+)", command_str)

                    if dest_port_match and source_port_match:
                        dest_port = int(dest_port_match.group(1))
                        source_port = int(source_port_match.group(1))
                        block_num = int(block_num_match.group(1)) if block_num_match else None

                        # Default IPs (client to server)
                        # Find client IP from source port (ephemeral port indicates client)
                        # Look back through entries to find which client is using this source port
                        src_ip = None
                        dest_ip = '172.20.0.10'  # Default server IP

                        for prev_entry in reversed(entries):
                            if prev_entry.get('entry_type') == 'packet':
                                # Check if this port was used by a client
                                if prev_entry.get('destPort') == source_port:
                                    src_ip = prev_entry.get('destIp')
                                    break
                                elif prev_entry.get('srcPort') == source_port:
                                    src_ip = prev_entry.get('srcIp')
                                    break

                        # If we couldn't find the client IP, try to extract from recent packets
                        if not src_ip:
                            # Look for the most recent packet to/from this source port
                            for prev_entry in reversed(entries):
                                if prev_entry.get('entry_type') == 'packet':
                                    if prev_entry.get('srcPort') == dest_port or prev_entry.get('destPort') == dest_port:
                                        # Found the server port, get its IP
                                        if prev_entry.get('srcPort') == dest_port:
                                            dest_ip = prev_entry.get('srcIp', dest_ip)
                                            src_ip = prev_entry.get('destIp')
                                        else:
                                            dest_ip = prev_entry.get('destIp', dest_ip)
                                            src_ip = prev_entry.get('srcIp')
                                        break

                        if src_ip:  # Only create entry if we found the source IP
                            payload = {}
                            if block_num is not None:
                                payload['blockNum'] = block_num

                            entries.append({
                                'entry_type': 'packet',
                                'direction': 'sent',
                                'srcIp': src_ip,
                                'srcPort': source_port,
                                'destIp': dest_ip,
                                'destPort': dest_port,
                                'payloadTag': cmd_type,
                                'payload': payload
                            })

            # Look for commands being sent to clients
            # These logs contain the actual TFTP source_port field
            elif 'Sending command to client' in message:
                # Extract: "Sending command to client 172.20.0.11 over 15001: {'type': 'rrq', 'source_port': 1024, ...}"
                # The "over 15001" is the control channel, but 'source_port' is the TFTP port
                match = re.search(r'Sending command to client ([0-9.]+) over (\d+): (\{.*)', message)
                if match:
                    client_ip = match.group(1)
                    control_port = int(match.group(2))  # Not used - this is control channel
                    command_str = match.group(3)

                    # Try to parse the command type and details
                    type_match = re.search(r"'type': '(\w+)'", command_str)
                    filename_match = re.search(r"'filename': '([^']+)'", command_str)
                    source_port_match = re.search(r"'source_port': (\d+)", command_str)

                    if type_match:
                        cmd_type = type_match.group(1).upper()

                        # Only handle RRQ/WRQ here (ACK is handled by "Sending ACK command" parser)
                        if cmd_type in ['RRQ', 'WRQ']:
                            # Use source_port from command, not control port
                            source_port = int(source_port_match.group(1)) if source_port_match else control_port
                            filename = filename_match.group(1) if filename_match else '?'

                            # Extract options if present
                            options_match = re.search(r"'options': (\{[^}]*\})", command_str)
                            payload = {'filename': filename}
                            if options_match:
                                payload['options'] = options_match.group(1)

                            # Assume server is at .10 (common pattern), client sending to port 69
                            dest_ip = '172.20.0.10'  # Default TFTP server IP
                            entries.append({
                                'entry_type': 'packet',
                                'direction': 'sent',
                                'srcIp': client_ip,
                                'srcPort': source_port,
                                'destIp': dest_ip,
                                'destPort': 69,
                                'payloadTag': cmd_type,
                                'payload': payload
                            })

            # Look for responses received - SKIP to avoid duplicates with "Sent packet" entries
            # The actual packet flow is captured by the spec's "Sent packet" and "Received packet" logs
            # elif 'Received response:' in message or ('✓' in message and 'response:' in message):
            #     # Extract response data
            #     match = re.search(r"response: (\{.*)", message)
            #     if match:
            #         response_str = match.group(1)
            #         # Try to extract opcode_name or opcode
            #         opcode_name_match = re.search(r"'opcode_name': '(\w+)'", response_str)
            #         opcode_match = re.search(r"'opcode': (\d+)", response_str)
            #         src_ip_match = re.search(r"'src_ip': '([0-9.]+)'", response_str)
            #         src_port_match = re.search(r"'src_port': (\d+)", response_str)
            #
            #         if opcode_name_match:
            #             opcode_name = opcode_name_match.group(1)
            #         elif opcode_match:
            #             opcode_name = f"OP{opcode_match.group(1)}"
            #         else:
            #             opcode_name = None
            #
            #         if opcode_name:
            #             src_ip = src_ip_match.group(1) if src_ip_match else None
            #             src_port = int(src_port_match.group(1)) if src_port_match else None
            #
            #             entries.append({
            #                 'entry_type': 'response',
            #                 'opcode_name': opcode_name,
            #                 'src_ip': src_ip,
            #                 'src_port': src_port,
            #                 'message': message
            #             })

            # Look for clock advances - only from "Action:" messages to avoid duplicates
            elif message.startswith('Action:') and 'Advance Clock by' in message:
                match = re.search(r'Advance Clock by (\d+)', message)
                if match:
                    delta = int(match.group(1))
                    entries.append({'entry_type': 'clock_advance', 'delta': delta, 'message': message})

            # Skip noisy messages like "Trying transition X [...]" - check BEFORE timeout check
            elif 'Trying transition' in message:
                pass  # Skip this message

            # Skip "Assume lastAction" messages - they're internal to symbolic execution
            elif 'Assume lastAction' in message:
                pass  # Skip this message

            # Skip "Received response" messages - they're redundant with packet entries
            elif 'Received response:' in message or 'response:' in message:
                pass  # Skip this message

            # Look for timeouts
            elif 'Timeout' in message or 'timeout' in message.lower():
                entries.append({'entry_type': 'timeout', 'message': message})

            # Look for specification mismatches
            # Skip "Transition X: DISABLED" and "Transition X is DISABLED" messages as they're noise
            # Distinguish between timeout-related mismatches (continue) and divergences (test stopped)
            elif ('✗' in message or 'does NOT match' in message) and not re.search(r'Transition \d+\s*(is |: )DISABLED', message):
                # Check if this is a timeout-related mismatch that allows continuation
                if 'SUT timeout does NOT match' in message and 'continue' in message:
                    entries.append({'entry_type': 'timeout_mismatch', 'message': message})
                elif 'test diverged' in message or 'ending test run' in message:
                    entries.append({'entry_type': 'test_diverged', 'message': message})
                else:
                    entries.append({'entry_type': 'spec_mismatch', 'message': message})

            # Skip successful spec matches - only show mismatches
            # elif '✓' in message and ('matches' in message.lower() or 'enabled' in message.lower()):
            #     entries.append({'entry_type': 'spec_match', 'message': message})

            # Look for action markers
            elif message.startswith('Action:'):

                entries.append({'entry_type': 'action', 'message': message})

    return entries


def collect_participants(entries: List[Dict[str, Any]]) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """
    Collect all unique client and server participants from parsed entries.
    Returns (client_participants, server_participants).
    Each participant is a tuple (id, label).
    """
    clients = set()
    servers = set()
    server_ips = set()

    # Identify server IPs (those receiving on port 69 or with low port numbers)
    for entry in entries:
        if entry.get('entry_type') != 'packet':
            continue

        if entry.get('destPort') == 69:
            server_ips.add(entry['destIp'])
        if entry.get('srcPort') == 69:
            server_ips.add(entry['srcIp'])

    # Classify all participants
    for entry in entries:
        if entry.get('entry_type') != 'packet':
            continue

        src_ip = entry.get('srcIp')
        src_port = entry.get('srcPort')
        dest_ip = entry.get('destIp')
        dest_port = entry.get('destPort')

        if src_ip and src_port is not None:
            src_id = get_participant_id(src_ip, src_port)
            src_label = get_participant_label(src_ip, src_port)

            if src_ip in server_ips or src_port < 1024:
                servers.add((src_id, src_label))
            else:
                clients.add((src_id, src_label))

        if dest_ip and dest_port is not None:
            dest_id = get_participant_id(dest_ip, dest_port)
            dest_label = get_participant_label(dest_ip, dest_port)

            if dest_ip in server_ips or dest_port < 1024:
                servers.add((dest_id, dest_label))
            else:
                clients.add((dest_id, dest_label))

    # Sort for consistent ordering
    client_list = sorted(clients)
    server_list = sorted(servers)

    return client_list, server_list


def generate_mermaid_diagram(entries: List[Dict[str, Any]]) -> str:
    """Generate a Mermaid sequence diagram from parsed log entries."""
    lines = ["sequenceDiagram"]

    # Collect all participants
    clients, servers = collect_participants(entries)

    # Declare participants (clients on left, servers on right)
    for client_id, client_label in clients:
        lines.append(f"    participant {client_id} as {client_label}")
    for server_id, server_label in servers:
        lines.append(f"    participant {server_id} as {server_label}")

    lines.append("")

    # Create a mapping from (ip, port) to participant ID
    participant_map = {}
    for client_id, client_label in clients:
        ip, port = client_label.split(":")
        participant_map[(ip, int(port))] = client_id
    for server_id, server_label in servers:
        ip, port = server_label.split(":")
        participant_map[(ip, int(port))] = server_id

    # Determine participants for notes
    first_participant = clients[0][0] if clients else (servers[0][0] if servers else None)
    last_participant = servers[-1][0] if servers else (clients[-1][0] if clients else None)

    # Process entries in chronological order
    total_clock = 0

    for entry in entries:
        entry_type = entry.get('entry_type')

        if entry_type == 'packet':
            # Show sent, expected, and received packets
            # Note: We show all to capture the full communication flow
            # Received packets are important for server->client messages like DATA
            if entry.get('direction') not in ['sent', 'expected', 'received']:
                continue

            src_ip = entry.get('srcIp')
            src_port = entry.get('srcPort')
            dest_ip = entry.get('destIp')
            dest_port = entry.get('destPort')

            if not all([src_ip, src_port is not None, dest_ip, dest_port is not None]):
                continue

            # Type checking - ensure we have valid values before using
            assert isinstance(src_ip, str) and isinstance(src_port, int)
            assert isinstance(dest_ip, str) and isinstance(dest_port, int)

            src_id = participant_map.get((src_ip, src_port), get_participant_id(src_ip, src_port))
            dest_id = participant_map.get((dest_ip, dest_port), get_participant_id(dest_ip, dest_port))

            payload_tag = entry.get('payloadTag', 'UNKNOWN')
            payload = entry.get('payload', {})
            payload_str = format_payload(payload_tag, payload)

            lines.append(f"    {src_id}->>{dest_id}: {payload_str}")

        elif entry_type == 'command':
            # Show command being sent from client as an arrow
            client_ip = entry.get('client_ip')
            client_port = entry.get('client_port')
            cmd_type = entry.get('command_type', 'CMD')

            if client_ip and client_port is not None:
                # Find the client participant
                client_id = participant_map.get((client_ip, client_port))
                if client_id:
                    # For ACK, ERROR, etc., we need to find the server they're sending to
                    # Try to find a server participant (typically port 69 or higher port from server)
                    server_id = None
                    # Look for a server in the participant map - typically has lower port or is .10 IP
                    for (ip, port), pid in participant_map.items():
                        if port < 1024 or ip.endswith('.10'):  # Common server patterns
                            server_id = pid
                            break

                    if server_id:
                        # Arrow from client to server
                        lines.append(f"    {client_id}->>{server_id}: {cmd_type}")
                    else:
                        # Fallback to note if we can't find server
                        lines.append(f"    Note right of {client_id}: ▶ Send {cmd_type}")

        # Response handling disabled - using packet entries instead to avoid duplicates
        # elif entry_type == 'response':
        #     # Show response from server as an arrow
        #     src_ip = entry.get('src_ip')
        #     src_port = entry.get('src_port')
        #     opcode_name = entry.get('opcode_name', 'RESPONSE')
        #
        #     if src_ip and src_port is not None:
        #         # Find the server participant
        #         server_id = participant_map.get((src_ip, src_port))
        #         if server_id:
        #             # Find a client to send the response to
        #             # Look for a client in the participant map (typically high port number)
        #             client_id = None
        #             for (ip, port), pid in participant_map.items():
        #                 if port >= 1024 and not ip.endswith('.10'):  # Common client pattern
        #                     client_id = pid
        #                     break
        #
        #             if client_id:
        #                 # Arrow from server to client
        #                 lines.append(f"    {server_id}->>{client_id}: {opcode_name}")
        #             else:
        #                 # Fallback to note if we can't find client
        #                 lines.append(f"    Note left of {server_id}: ◀ Recv {opcode_name}")

        elif entry_type == 'clock_advance':
            delta = entry.get('delta', 0)
            total_clock += delta
            if first_participant and last_participant:
                lines.append(f"    Note over {first_participant},{last_participant}: ⏰ Clock +{delta}s (total: {total_clock}s)")

        elif entry_type == 'timeout':
            message = entry.get('message', '')
            if first_participant and last_participant:
                # Extract timeout details if possible
                clean_msg = message.replace('⏱', '').strip()
                lines.append(f"    Note over {first_participant},{last_participant}: ⏱ {clean_msg}")

        elif entry_type == 'timeout_mismatch':
            # Timeout-related spec mismatch that allows test to continue
            message = entry.get('message', '')
            if first_participant and last_participant:
                clean_msg = message.replace('✗', '').strip()
                lines.append(f"    Note over {first_participant},{last_participant}: ⚠️ {clean_msg}")

        elif entry_type == 'test_diverged':
            # Test diverged or ended - critical mismatch
            message = entry.get('message', '')
            if first_participant and last_participant:
                clean_msg = message.replace('✗', '').strip()
                lines.append(f"    Note over {first_participant},{last_participant}: ❌ {clean_msg}")

        elif entry_type == 'spec_mismatch':
            message = entry.get('message', '')
            if first_participant and last_participant:
                # Clean up the message for display
                clean_msg = message.replace('✗', '').strip()
                lines.append(f"    Note over {first_participant},{last_participant}: ✗ SPEC MISMATCH: {clean_msg}")

        elif entry_type == 'spec_match':
            message = entry.get('message', '')
            if first_participant and last_participant:
                # Clean up the message for display
                clean_msg = message.replace('✓', '').strip()
                if 'matches' in clean_msg.lower():
                    lines.append(f"    Note over {first_participant},{last_participant}: ✓ {clean_msg}")

    return "\n".join(lines)


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python log_to_mermaid.py input.log [output.mmd]", file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    # Parse log file
    entries = parse_log_file(input_file)

    if not entries:
        print("Warning: No entries found in log file", file=sys.stderr)

    # Count different entry types
    packets = [e for e in entries if e.get('entry_type') == 'packet']
    events = [e for e in entries if e.get('entry_type') != 'packet']

    print(f"Found {len(packets)} packets and {len(events)} events", file=sys.stderr)

    # Generate Mermaid diagram
    diagram = generate_mermaid_diagram(entries)

    # Write output
    if output_file:
        with open(output_file, 'w') as f:
            f.write(diagram)
        print(f"Mermaid diagram written to {output_file}")
    else:
        print(diagram)


if __name__ == "__main__":
    main()
