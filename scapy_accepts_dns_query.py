#!/usr/bin/env python
# source: https://jasonmurray.org/posts/2020/scapydns/

# Import scapy libraries
# from scapy.all import * # type: ignore
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR
from scapy.sendrecv import sniff, sendp
from scapy.layers.l2 import Ether

# let us not run this on windows.
# from scapy.interfaces import get_if_list

# # list available interfaces
# print("Avaliable interfaces:", *get_if_list())

# # let the user choose
# net_interface = input("Choose an interface: ")
# assert net_interface in get_if_list(), "Invalid interface"


# Berkeley Packet Filter for sniffing specific DNS packet only
packet_filter = " and ".join(
    [
        "udp dst port 53",  # Filter UDP port 53
        "udp[10] & 0x80 = 0",  # DNS queries only
        # "dst host 127.0.0.1",  # IP dst <ip>
    ]
)


# Function that replies to DNS query
def dns_reply(packet):
    print("DNS query received")
    # Construct the DNS packet
    # Construct the Ethernet header by looking at the sniffed packet
    eth = Ether(src=packet[Ether].dst, dst=packet[Ether].src)

    # Construct the IP header by looking at the sniffed packet
    ip = IP(src=packet[IP].dst, dst=packet[IP].src)

    # Construct the UDP header by looking at the sniffed packet
    udp = UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)

    # Construct the DNS response by looking at the sniffed packet and manually
    dns = DNS(
        id=packet[DNS].id,
        qd=packet[DNS].qd,
        aa=1,
        rd=0,
        qr=1,
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0,
        ar=DNSRR(rrname=packet[DNS].qd.qname, type="A", ttl=600, rdata="1.2.3.4"),
    )

    # Put the full packet together
    response_packet = eth / ip / udp / dns

    # Send the DNS response
    sendp(response_packet, iface=net_interface)

print("Sniffing for 1 DNS query matching the filter and sending a DNS reply")
# Sniff for a DNS query matching the 'packet_filter' and send a specially crafted reply
sniff(filter=packet_filter, prn=dns_reply, iface="vlan0", store=0, count=1)
# sniff(filter=packet_filter, prn=dns_reply, store=0, iface=net_interface, count=1)

# this code seems to be fabricated.