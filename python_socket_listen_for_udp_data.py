import socket
from scapy.layers.dns import DNS, DNSQR, DNSRR

# Define unicast address and port
UDP_IP = "127.0.0.1"  # Replace with your unicast IP
UDP_PORT = 53  # Replace with your desired port
# Create and bind the socket
print(f"Listening for UDP packets on {UDP_IP}:{UDP_PORT}")
# Continuously listen for incoming packets

if False:
    from scapy.layers.inet import UDP, IP
    # need to use raw socket type.
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.bind((UDP_IP, UDP_PORT)) # did not filter on port.
    while True:
        raw_data = sock.recv(65535)
    #     # this is not the udp data we want. it has the wrong sport, wrong dport.
        ip_packet = IP(raw_data)
        if ip_packet.dst != UDP_IP: continue
        print(ip_packet)
        print("ip packet fields:", ip_packet.fields)
        print("ip packet layers:", ip_packet.layers()) # has layer ip, udp, dns
        if ip_packet.haslayer(UDP):
            udp_packet = ip_packet[UDP]
            if udp_packet.dport != UDP_PORT: continue
            print(udp_packet)
            print("UDP packet is dns query:", udp_packet.haslayer(DNSQR))
            print(udp_packet.fields)
            print(udp_packet.layers())


if True:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    while True:
        data, addr = sock.recvfrom(65535)
        print(f"Received message: {data.hex()} from {addr}")
        # packet received, parsed.
        dns_request_packet:DNS = DNS(data)
        # DNS Qry b'baidu.com.'
        print(dns_request_packet)
        # Packet fields: {'id': 6292, 'qr': 0, 'opcode': 0, 'aa': 0, 'tc': 0, 'rd': 1, 'ra': 0, 'z': 0, 'ad': 1, 'cd': 0, 'rcode': 0, 'qdcount': 1, 'ancount': 0, 'nscount': 0, 'arcount': 1, 'qd': [<DNSQR  qname=b'baidu.com.' qtype=A unicastresponse=0 qclass=IN |>], 'an': [], 'ns': [], 'ar': [<DNSRROPT  rrname=b'.' type=OPT rclass=1232 extrcode=0 version=0 z=0 rdata=[<EDNS0COOKIE  optcode=COOKIE optlen=8 client_cookie=6a298f936bb99ee0 server_cookie= |>] |>]}
        # print("DNS packet fields:", dns_request_packet.fields)
        if dns_request_packet.haslayer(DNSQR):
            dnsqr: DNSQR = dns_request_packet[DNSQR]
            # print("Fields of dnsqr:", dnsqr.fields)
            # {'qname': b'baidu.com.', 'qtype': 1, 'unicastresponse': 0, 'qclass': 1}
            qname = dnsqr.qname
            print("Qname:", qname)
            # either forge one or just get from a DNS server
            if True:
                from scapy.all import *
                # get one from 8.8.8.8
                response_packet = sr1(
                    IP(dst="8.8.8.8") / UDP(dport=53) / dns_request_packet # working as expected. but better not to use broadcast. use a specific interface, a specific ip address instead.
                )
                print("Response packet:", response_packet)
                print("Response packet type:", type(response_packet)) # scapy.layers.l2.Dot1Q
                if response_packet.haslayer(DNS):
                    print("Response has dns layer")
                    # send the response back to the client 
                    sock.sendto(bytes(response_packet[DNS]), addr)
                else:
                    print("Response does not have dns layer")
            if False:
                response_packet = DNS(
                            id=dns_request_packet.id,
                            qr=1,  # Response flag
                            aa=1,  # Authoritative answer
                            qd=dns_request_packet.qd,
                            # an=None,
                            an=DNSRR(rrname=qname, rdata="1.2.3.4"),
                        )
                # send the response back to the client
                sock.sendto(bytes(response_packet), addr)