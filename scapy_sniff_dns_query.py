from scapy.all import *


# packet filter is not working at all. what dependency is missing?
packet_filter = " and ".join(
    [
        # "tcp",  # Filter TCP packets
        "udp",  # Filter UDP packets
        # below seems not working
        # "udp dst port 53",  # Filter UDP port 53
        # "udp[10] & 0x80 = 0",  # DNS queries only
        # "dst host 127.0.0.1",  # IP dst <ip>
    ]
)

# must sniff on physical interface, not on vlan interface

# working
sniff(filter=packet_filter, prn=lambda x: x.summary(), iface="enp2s0")
# sniff(filter="tcp", prn=lambda x: x.summary(), iface="enp2s0")

# not working
# sniff(filter="tcp", prn=lambda x: x.summary(), iface="vlan0")

# not working. must specify interface.
# sniff(filter="tcp", prn=lambda x: x.summary())
# sniff(filter=packet_filter, prn=lambda x: x.summary())