#!/usr/bin/env python3
"""
Network Auto-Detection Utility

Automatically detects:
- Active network interface (with internet connectivity)
- Local IP address
- Gateway IP
- Network CIDR

Usage:
    from vajra.common.network import get_active_interface, get_local_ip
    
    interface = get_active_interface()  # 'eth0', 'enp0s5', etc.
    ip = get_local_ip()                 # '192.168.1.100'
"""

import subprocess
import socket
import re
import os
import sys
import json
from typing import Optional, Tuple, Dict, List

def run_command(cmd: str) -> str:
    """Run a shell command and return output"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip()
    except Exception:
        return ""


def get_active_interface() -> str:
    """
    Auto-detect the active network interface with internet connectivity.
    
    Tries multiple methods:
    1. Interface with default route
    2. Interface with IP and is UP
    3. Common interface names
    
    Returns:
        Interface name (e.g., 'eth0', 'enp0s5', 'wlan0')
    """
    # Method 1: Get interface from default route
    route_output = run_command("ip route show default 2>/dev/null")
    if route_output:
        # Parse: "default via 192.168.1.1 dev eth0"
        match = re.search(r'dev\s+(\S+)', route_output)
        if match:
            interface = match.group(1)
            if interface and interface != 'lo':
                return interface
    
    # Method 2: Get interface with assigned IP that is UP
    ip_output = run_command("ip -o addr show 2>/dev/null")
    for line in ip_output.split('\n'):
        if 'inet ' in line and 'scope global' in line:
            match = re.search(r'^\d+:\s+(\S+)', line)
            if match:
                interface = match.group(1)
                if interface and interface != 'lo':
                    return interface
    
    # Method 3: Check common interface names
    common_interfaces = [
        'eth0', 'eth1', 
        'enp0s3', 'enp0s5', 'enp0s8', 'enp1s0',
        'ens3', 'ens5', 'ens33', 'ens160',
        'wlan0', 'wlp2s0',
        'em1', 'em0',
    ]
    
    for iface in common_interfaces:
        if os.path.exists(f'/sys/class/net/{iface}'):
            # Check if interface is UP
            state = run_command(f"cat /sys/class/net/{iface}/operstate 2>/dev/null")
            if state == 'up':
                return iface
    
    # Method 4: Just return first non-lo interface
    interfaces = run_command("ls /sys/class/net 2>/dev/null").split()
    for iface in interfaces:
        if iface != 'lo':
            return iface
    
    # Fallback
    return 'eth0'


def get_local_ip(interface: str = None) -> str:
    """
    Get the local IP address.
    
    Args:
        interface: Specific interface (optional, auto-detect if None)
    
    Returns:
        IP address string (e.g., '192.168.1.100')
    """
    if interface is None:
        interface = get_active_interface()
    
    # Method 1: Get IP from specific interface
    ip_output = run_command(f"ip -4 addr show {interface} 2>/dev/null")
    if ip_output:
        match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', ip_output)
        if match:
            return match.group(1)
    
    # Method 2: Connect to external server to determine local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    
    # Method 3: Get any non-localhost IP
    ip_output = run_command("hostname -I 2>/dev/null")
    if ip_output:
        ips = ip_output.split()
        for ip in ips:
            if ip and not ip.startswith('127.'):
                return ip
    
    # Fallback
    return '127.0.0.1'


def get_gateway_ip(interface: str = None) -> str:
    """
    Get the gateway IP address.
    
    Returns:
        Gateway IP (e.g., '192.168.1.1')
    """
    route_output = run_command("ip route show default 2>/dev/null")
    if route_output:
        match = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', route_output)
        if match:
            return match.group(1)
    
    # Fallback: guess from local IP
    local_ip = get_local_ip(interface)
    if local_ip and local_ip != '127.0.0.1':
        parts = local_ip.split('.')
        parts[3] = '1'
        return '.'.join(parts)
    
    return '192.168.1.1'


def get_local_addresses() -> List[str]:
    """Get every IPv4 and IPv6 address on the host"""
    try:
        interfaces = json.loads(run_command("ip -j addr show 2>/dev/null"))
        return [
            address["local"]
            for interface in interfaces
            for address in interface.get("addr_info", [])
            if address.get("local")
        ]
    except (json.JSONDecodeError, TypeError, AttributeError):
        return []


def get_default_gateways() -> List[str]:
    """Get every IPv4 and IPv6 default gateway, including multipath routes"""
    gateways = []
    for family in ("-4", "-6"):
        try:
            routes = json.loads(run_command(f"ip -j {family} route show default 2>/dev/null"))
            gateways += [
                nexthop["gateway"]
                for route in routes
                for nexthop in [route] + route.get("nexthops", [])
                if nexthop.get("gateway")
            ]
        except (json.JSONDecodeError, TypeError, AttributeError):
            continue
    return gateways


def get_network_cidr(interface: str = None) -> str:
    """
    Get the network CIDR.
    
    Returns:
        Network CIDR (e.g., '192.168.1.0/24')
    """
    if interface is None:
        interface = get_active_interface()
    
    ip_output = run_command(f"ip -4 addr show {interface} 2>/dev/null")
    if ip_output:
        match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', ip_output)
        if match:
            ip = match.group(1)
            prefix = match.group(2)
            # Calculate network address
            parts = ip.split('.')
            if prefix == '24':
                parts[3] = '0'
            elif prefix == '16':
                parts[2] = '0'
                parts[3] = '0'
            return f"{'.'.join(parts)}/{prefix}"
    
    return '192.168.1.0/24'


def get_all_network_info() -> Dict[str, str]:
    """
    Get all network information.
    
    Returns:
        Dict with interface, ip, gateway, network
    """
    interface = get_active_interface()
    return {
        'interface': interface,
        'ip': get_local_ip(interface),
        'gateway': get_gateway_ip(interface),
        'network': get_network_cidr(interface),
    }


def print_network_info():
    """Print network information"""
    info = get_all_network_info()
    print(f"Interface: {info['interface']}")
    print(f"IP Address: {info['ip']}")
    print(f"Gateway: {info['gateway']}")
    print(f"Network: {info['network']}")


if __name__ == "__main__":
    # When run directly, print info or return specific value
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == 'interface':
            print(get_active_interface())
        elif cmd == 'ip':
            print(get_local_ip())
        elif cmd == 'gateway':
            print(get_gateway_ip())
        elif cmd == 'network':
            print(get_network_cidr())
        elif cmd == 'all':
            print_network_info()
        else:
            print(f"Unknown command: {cmd}")
            print("Usage: python3 -m vajra.common.network [interface|ip|gateway|network|all]")
    else:
        print_network_info()
