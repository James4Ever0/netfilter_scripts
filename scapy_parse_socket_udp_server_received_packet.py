# test with: echo "Hello Scapy" | nc -u localhost 9999
import socket
from scapy.layers.inet import IP, UDP

# Setup raw socket to capture UDP packets
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
sock.bind(("0.0.0.0", 9999))  # Bind to port 9999

print("Listening for UDP packets on port 9999...")

while True:
    # Receive packet (includes IP header + UDP payload)
    packet_data, addr = sock.recvfrom(65535)

    # Parse with Scapy
    scapy_packet = IP(packet_data)

    # Check if it's a UDP packet
    if scapy_packet.haslayer(UDP):
        udp_layer = scapy_packet[UDP]

        # Verify destination port (optional)
        if udp_layer.dport == 9999:
            print(f"\nReceived UDP packet from {addr[0]}:{udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            print(f"Payload length: {len(udp_layer.payload)} bytes")

            # Access raw payload bytes
            payload_bytes = bytes(udp_layer.payload)
            print(f"Payload (hex): {payload_bytes.hex()}")

            # Example: Convert payload to string if it's text
            try:
                payload_text = payload_bytes.decode("utf-8")
                print(f"Payload (text): {payload_text}")
            except UnicodeDecodeError:
                print("Payload is not UTF-8 text")
