# Pegasus Network Capture and Remote Connect

**Author:** Muhammad Sobri Maulana  

Pegasus Network Capture and Remote Connect is a Python-based utility designed for network packet capture and analysis as well as simulating remote connection functionalities. It emphasizes ethical and safe practices for handling network traffic and remote access. This tool is intended for network administrators, developers, and researchers who need a flexible and customizable solution.

## Features

- **Network Packet Capture:** Capture network packets and save them in `.pcap` format using Scapy.
- **Packet Analysis:** Process and summarize captured packets during the sniffing session.
- **Remote Connection Simulation:** Simulate a VNC connection to a remote server for basic handshake operations.

## Requirements

- Python 3.7+
- Libraries:
  - `scapy` for packet capture and analysis

Install the required libraries with:

```bash
pip install scapy
```

## Installation

Clone the repository and navigate to the project directory:

```bash
$ git clone https://github.com/your-repo/pegasus-network-capture.git
$ cd pegasus-network-capture
```

## Usage

### Network Packet Capture

The following script captures network packets on a specified interface and saves them in `.pcap` format.

```python
from scapy.all import sniff, wrpcap

def packet_callback(packet):
    """Callback function to process captured packets."""
    print(f"Packet captured: {packet.summary()}")
    return packet

def capture_packets(interface, output_file, packet_count=100):
    """
    Capture packets on a specified interface and save them to a file.

    :param interface: Network interface to capture packets on.
    :param output_file: File to save the captured packets.
    :param packet_count: Number of packets to capture.
    """
    print(f"Starting packet capture on interface {interface}.")
    packets = sniff(iface=interface, count=packet_count, prn=packet_callback)
    print(f"Capture complete. Writing to {output_file}.")
    wrpcap(output_file, packets)

if __name__ == "__main__":
    # Example usage
    network_interface = "eth0"  # Replace with your interface name
    output_pcap = "network_capture.pcap"
    packet_limit = 50

    capture_packets(network_interface, output_pcap, packet_limit)
```

### Remote Connection Simulation

The script below demonstrates a basic simulation of a VNC connection using Python sockets.

```python
import socket

def connect_to_vnc(server_ip, port=5900):
    """
    Connect to a VNC server.

    :param server_ip: IP address of the VNC server.
    :param port: Port to connect to (default is 5900 for VNC).
    """
    try:
        print(f"Connecting to VNC server at {server_ip}:{port}...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as vnc_socket:
            vnc_socket.connect((server_ip, port))
            print("Connected to VNC server.")
            # Placeholder for VNC handshake or data transfer
            print("Performing handshake...")
            vnc_socket.send(b"RFB 003.003\n")
            response = vnc_socket.recv(1024)
            print(f"Server response: {response}")
    except Exception as e:
        print(f"Error connecting to VNC server: {e}")

if __name__ == "__main__":
    # Example usage
    vnc_server_ip = "192.168.8.1"  # Replace with the actual VNC server IP
    vnc_server_port = 5900

    connect_to_vnc(vnc_server_ip, vnc_server_port)
```

### Function Descriptions

#### `packet_callback(packet)`
Processes captured packets and displays a summary.

#### `capture_packets(interface, output_file, packet_count=100)`
Captures network packets on a specified interface and saves them in `.pcap` format.

#### `connect_to_vnc(server_ip, port=5900)`
Simulates a VNC connection by opening a socket and performing a basic handshake operation.

## Example Scenarios

1. **Network Packet Capture:** Use `capture_packets` to log and analyze traffic for troubleshooting or research.
2. **VNC Simulation:** Employ `connect_to_vnc` to test basic remote connectivity operations.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

For any inquiries or contributions, please contact Muhammad Sobri Maulana at [your-email@example.com].
