#!/usr/bin/env python3
"""
Convert ITF JSON counterexample traces to Mermaid sequence diagrams.

This script reads an ITF JSON file (as per https://apalache-mc.org/docs/adr/015adr-trace.html)
and generates a Mermaid sequence diagram showing the message flow between clients and servers.

Usage:
    python itf_to_mermaid.py input.itf.json [output.mmd]
"""

import json
import sys
from typing import Any, Dict, List, Set, Tuple


def parse_bigint(_value: Any) -> int:
    """Parse ITF bigint value."""
    if isinstance(_value, dict) and "#bigint" in _value:
        return int(_value["#bigint"])
    return int(_value)


def parse_variant(_variant: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Parse ITF variant (tagged union) value."""
    tag = _variant["tag"]
    value = _variant["value"]
    return tag, value


def parse_packet(_packet: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a UDP packet from ITF format."""
    result = {
        "srcIp": _packet["srcIp"],
        "srcPort": parse_bigint(_packet["srcPort"]),
        "destIp": _packet["destIp"],
        "destPort": parse_bigint(_packet["destPort"]),
    }
    
    # Parse the payload variant
    tag, payload_value = parse_variant(_packet["payload"])
    result["payloadTag"] = tag
    result["payload"] = {}
    
    # Parse payload fields
    for key, value in payload_value.items():
        if key == "opcode":
            result["payload"][key] = parse_bigint(value)
        elif key in ["blockNum", "data", "errorCode"]:
            result["payload"][key] = parse_bigint(value)
        elif key == "options":
            # Parse options map
            options = {}
            if "#map" in value:
                for opt_key, opt_value in value["#map"]:
                    options[opt_key] = parse_bigint(opt_value)
            result["payload"][key] = options
        else:
            result["payload"][key] = value
    
    return result


def parse_packets_set(_packets_value: Any) -> Set[Tuple[str, int, str, int, str, str]]:
    """
    Parse the packets set and return a set of tuples representing packets.
    Each tuple: (srcIp, srcPort, destIp, destPort, payloadTag, payload_str)
    """
    packets = set()
    
    if isinstance(_packets_value, dict) and "#set" in _packets_value:
        for packet_data in _packets_value["#set"]:
            parsed = parse_packet(packet_data)
            
            # Create a string representation of the payload
            payload_str = format_payload(parsed["payloadTag"], parsed["payload"])
            
            packet_tuple = (
                parsed["srcIp"],
                parsed["srcPort"],
                parsed["destIp"],
                parsed["destPort"],
                parsed["payloadTag"],
                payload_str
            )
            packets.add(packet_tuple)
    
    return packets


def format_payload(_tag: str, _payload: Dict[str, Any]) -> str:
    """Format payload for display in sequence diagram."""
    if _tag == "RRQ":
        filename = _payload.get("filename", "?")
        options = _payload.get("options", {})
        if options:
            opts_str = ", ".join(f"{k}={v}" for k, v in sorted(options.items()))
            return f"RRQ({filename}, {opts_str})"
        return f"RRQ({filename})"
    elif _tag == "WRQ":
        filename = _payload.get("filename", "?")
        options = _payload.get("options", {})
        if options:
            opts_str = ", ".join(f"{k}={v}" for k, v in sorted(options.items()))
            return f"WRQ({filename}, {opts_str})"
        return f"WRQ({filename})"
    elif _tag == "DATA":
        block_num = _payload.get("blockNum", "?")
        data_len = _payload.get("data", "?")
        return f"DATA(blk={block_num}, {data_len}B)"
    elif _tag == "ACK":
        block_num = _payload.get("blockNum", "?")
        return f"ACK(blk={block_num})"
    elif _tag == "OACK":
        options = _payload.get("options", {})
        opts_str = ", ".join(f"{k}={v}" for k, v in sorted(options.items()))
        return f"OACK({opts_str})"
    elif _tag == "ERROR":
        error_code = _payload.get("errorCode", "?")
        msg = _payload.get("msg", "")
        return f"ERROR({error_code}, {msg})"
    else:
        return _tag


def get_participant_id(_ip: str, _port: int) -> str:
    """Generate a valid Mermaid participant ID for an IP:port pair."""
    # Replace dots with underscores for valid Mermaid IDs
    ip_part = _ip.replace(".", "_")
    return f"ip{ip_part}_port{_port}"


def get_participant_label(_ip: str, _port: int) -> str:
    """Generate a human-readable label for an IP:port pair."""
    return f"{_ip}:{_port}"


def collect_participants(_trace: Dict[str, Any]) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """
    Collect all unique client and server participants from the trace.
    Returns (client_participants, server_participants).
    Each participant is a tuple (id, label).
    """
    clients = set()
    servers = set()
    
    # Assume server IP is 10.0.0.1 (common pattern in TFTP)
    # We'll detect it by looking at packets destined to port 69
    server_ips = set()
    
    for state in _trace["states"]:
        packets_value = state.get("packets", {})
        if isinstance(packets_value, dict) and "#set" in packets_value:
            for packet_data in packets_value["#set"]:
                parsed = parse_packet(packet_data)
                
                # Port 69 is the standard TFTP server port
                if parsed["destPort"] == 69:
                    server_ips.add(parsed["destIp"])
                
                # Collect all participants
                src_id = get_participant_id(parsed["srcIp"], parsed["srcPort"])
                src_label = get_participant_label(parsed["srcIp"], parsed["srcPort"])
                dest_id = get_participant_id(parsed["destIp"], parsed["destPort"])
                dest_label = get_participant_label(parsed["destIp"], parsed["destPort"])
                
                # Classify as client or server based on IP
                if parsed["srcIp"] in server_ips or parsed["srcPort"] < 1024:
                    servers.add((src_id, src_label))
                else:
                    clients.add((src_id, src_label))
                    
                if parsed["destIp"] in server_ips or parsed["destPort"] < 1024:
                    servers.add((dest_id, dest_label))
                else:
                    clients.add((dest_id, dest_label))
    
    # Sort for consistent ordering
    client_list = sorted(clients)
    server_list = sorted(servers)
    
    return client_list, server_list


def generate_mermaid_diagram(_trace: Dict[str, Any]) -> str:
    """Generate a Mermaid sequence diagram from an ITF trace."""
    lines = ["sequenceDiagram"]
    
    # Collect all participants
    clients, servers = collect_participants(_trace)
    
    # Declare participants (clients on left, servers on right)
    for client_id, client_label in clients:
        lines.append(f"    participant {client_id} as {client_label}")
    for server_id, server_label in servers:
        lines.append(f"    participant {server_id} as {server_label}")
    
    lines.append("")
    
    # Create a mapping from (ip, port) to participant ID
    participant_map = {}
    for client_id, client_label in clients:
        # Extract IP and port from label (IP:PORT format)
        ip, port = client_label.split(":")
        participant_map[(ip, int(port))] = client_id
    for server_id, server_label in servers:
        ip, port = server_label.split(":")
        participant_map[(ip, int(port))] = server_id
    
    # Process states
    states = _trace["states"]
    previous_packets = set()
    previous_clock = None
    
    for i, state in enumerate(states):
        state_index = state["#meta"]["index"]
        
        # Get clock value
        clock_value = None
        if "clock" in state:
            clock_value = parse_bigint(state["clock"])
        
        # Show clock increments
        if previous_clock is not None and clock_value is not None and clock_value != previous_clock:
            # Use first client and last server for the note span
            first_participant = clients[0][0] if clients else servers[0][0]
            last_participant = servers[-1][0] if servers else clients[-1][0]
            lines.append(f"    Note over {first_participant},{last_participant}: Clock: {previous_clock} → {clock_value}")
        
        # Get current packets
        current_packets = parse_packets_set(state.get("packets", {}))
        
        # Find new packets (added in this step)
        new_packets = current_packets - previous_packets
        
        # Add messages for new packets
        for packet in sorted(new_packets):
            src_ip, src_port, dest_ip, dest_port, payload_tag, payload_str = packet
            src_id = participant_map.get((src_ip, src_port), get_participant_id(src_ip, src_port))
            dest_id = participant_map.get((dest_ip, dest_port), get_participant_id(dest_ip, dest_port))
            
            lines.append(f"    {src_id}->>{dest_id}: {payload_str}")
        
        previous_packets = current_packets
        previous_clock = clock_value
    
    return "\n".join(lines)


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python itf_to_mermaid.py input.itf.json [output.mmd]", file=sys.stderr)
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Read ITF JSON
    with open(input_file, 'r') as f:
        trace = json.load(f)
    
    # Generate Mermaid diagram
    diagram = generate_mermaid_diagram(trace)
    
    # Write output
    if output_file:
        with open(output_file, 'w') as f:
            f.write(diagram)
        print(f"Mermaid diagram written to {output_file}")
    else:
        print(diagram)


if __name__ == "__main__":
    main()
