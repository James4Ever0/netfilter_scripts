from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.sendrecv import sr1

# Send a DNS query to Google's public DNS server (8.8.8.8)
dns_response = sr1(
    IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="www.example.com"))
)

# Extract and print the resolved IP addresses
if dns_response and dns_response.haslayer(DNS):
    for i in range(dns_response[DNS].ancount):  # Iterate over all answers
        answer = dns_response[DNS].an[i]
        if isinstance(answer, DNSRR) and answer.type == 1:  # Type 1 = A record
            print(f"Resolved IP: {answer.rdata}")
