# if we can understand what the client asks and the dns server responds with, we can decide whether to allow the connection to an ip with a hostname and a port or not.

import socket
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR

# on linux, dns is served at 127.0.0.53:53

# Setup raw socket to capture UDP packets
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
bind_address = "127.0.0.1"
# bind_address = "192.168.30.14"
sock.bind((bind_address, 53))  # Bind to port 53

print("Listening for UDP packets on port 53...")

while True:
    # Receive packet (includes IP header + UDP payload)
    packet_data, addr = sock.recvfrom(65535)
    src_ip = addr[0]
    if src_ip != "127.0.0.1": continue
    # print("Packet received from:", addr) # seems there is no port in addr. port is always zero.
    print("Packet received from:", addr[0])

    # Parse with Scapy
    scapy_packet = IP(packet_data)

    # Check if it's a UDP packet
    if scapy_packet.haslayer(UDP):
        udp_layer = scapy_packet[UDP]

        # Verify destination port (optional)
        if udp_layer.dport == 53:
            # Check if it's a DNS packet
            if scapy_packet.haslayer(DNSRR):
                dns_layer = scapy_packet[DNSRR]
                print(f"DNS Query: {dns_layer.qname.decode()}")
                print(f"DNS Answer: {dns_layer.rdata.decode()}")