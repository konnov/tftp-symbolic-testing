#!/usr/bin/env python3
"""
Convert Python test harness log files to Mermaid sequence diagrams.

This script reads a Python log file from the test harness and generates a 
Mermaid sequence diagram showing the TFTP message flow between clients and servers.

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
                    else:
                        packet_data['direction'] = 'expected'
                    
                    packet_data['entry_type'] = 'packet'
                    entries.append(packet_data)
            
            # Look for clock advances
            elif 'Advance Clock by' in message or 'Clock advanced by' in message:
                match = re.search(r'(?:Advance Clock by|Clock advanced by) (\d+)', message)
                if match:
                    delta = int(match.group(1))
                    entries.append({'entry_type': 'clock_advance', 'delta': delta, 'message': message})
            
            # Look for timeouts
            elif 'Timeout' in message or 'timeout' in message.lower():
                entries.append({'entry_type': 'timeout', 'message': message})
            
            # Look for specification mismatches
            elif '✗' in message or 'does NOT match' in message or 'DISABLED' in message:
                entries.append({'entry_type': 'spec_mismatch', 'message': message})
            
            # Look for successful matches
            elif '✓' in message and ('matches' in message.lower() or 'enabled' in message.lower()):
                entries.append({'entry_type': 'spec_match', 'message': message})
            
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
            # Only show sent and expected packets (to avoid duplicates)
            if entry.get('direction') not in ['sent', 'expected']:
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
