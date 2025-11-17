from scapy.all import *

# Sniffing 5 packets
capture = sniff(count=5)
capture.summary()