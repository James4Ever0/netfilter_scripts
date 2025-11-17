from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

# Define the DNS response mappings
dns_records = {
    b"example.com.": "192.168.1.100",
    b"test.com.": "192.168.1.101",
    b"baidu.com.": "127.0.0.1",
}


def dns_response(packet):
    if packet.haslayer(IP):
        # check for source ip and dest ip
        ip_packet = packet[IP]
        # {'version': 4, 'ihl': 5, 'tos': 0, 'len': 253, 'id': 26759, 'flags': <Flag 2 (DF)>, 'frag': 0, 'ttl': 1, 'proto': 17, 'chksum': 4659, 'src': '127.0.0.53', 'dst': '127.0.0.1', 'options': []}
        if ip_packet.dst != "127.0.0.1":
            return
        # print("ip packet fields", ip_packet.fields)
    if packet.haslayer(UDP):
        udp_packet = packet[UDP]
        if udp_packet.dport != 53:
            return
        # only has sport, dport, len, chksum
        # print("udp packet fields", udp_packet.fields)
    # Check if the packet is a DNS query
    if packet.haslayer(DNSQR):
        query_name = packet[DNSQR].qname
        # do not decode yet or we may have an issue.
        print(f"Received query for: {query_name}")
        # Check if the query matches our records
        if query_name in dns_records:
            response_ip = dns_records[query_name]
            print(f"Responding with IP: {response_ip}")
            # Create a DNS response packet
            response = (
                IP(dst=packet[IP].src, src=packet[IP].dst)
                / UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)
                / DNS(
                    id=packet[DNS].id,
                    qr=1,  # Response flag
                    aa=1,  # Authoritative answer
                    qd=packet[DNS].qd,
                    an=DNSRR(rrname=query_name, rdata=response_ip),
                )
            )
            send(response, verbose=0)
        else:
            print("No matching record found.")
    else:
        print("Not a DNS query.")


# Sniff incoming packets and process them
print("Starting mock DNS server...")
# so you do need to get this interface right.
# use ip addr to check for interface and address correspondance.
sniff(filter="udp port 53", prn=dns_response, iface="lo")
# it says "connection refused", opposed to socket connection accepted.